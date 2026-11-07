package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/engine"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/store"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

type reviewProvider struct {
	trafficCalls, statusCalls, controls int
	fail                                bool
}

func (p *reviewProvider) GetTraffic(context.Context, domain.Account, string) (float64, error) {
	p.trafficCalls++
	return 200, nil
}
func (p *reviewProvider) GetInstanceStatus(context.Context, domain.Account, string) (string, error) {
	p.statusCalls++
	return domain.StatusRunning, nil
}
func (p *reviewProvider) ControlInstance(context.Context, domain.Account, string, string, string) error {
	p.controls++
	if p.fail {
		return fmt.Errorf("remote accepted but reply lost: diagnostic-cause-471 test-only-secret")
	}
	return nil
}
func (p *reviewProvider) GetAccountBalance(context.Context, domain.Account, string) (aliyun.BillingBalance, error) {
	return aliyun.BillingBalance{}, nil
}
func (p *reviewProvider) GetInstanceBill(context.Context, domain.Account, string, string) (aliyun.BillingBill, error) {
	return aliyun.BillingBill{}, nil
}
func reviewFixture(t *testing.T) (*store.Store, *engine.Engine, *reviewProvider, http.Handler, []*http.Cookie, map[string]string) {
	t.Helper()
	st := initializedAuthStore(t)
	p := &reviewProvider{fail: true}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	e := engine.New(st, p, notify.New(), logger, 2)
	h := New(st, e, fstest.MapFS{"index.html": {Data: []byte("ok")}}, logger).Handler()
	s, c := loginCookies(t, h)
	return st, e, p, h, []*http.Cookie{s, c}, map[string]string{"X-CDT-CSRF": c.Value}
}
func reviewRefresh(t *testing.T, h http.Handler, c []*http.Cookie, headers map[string]string) domain.Job {
	t.Helper()
	r := doRequest(t, h, "POST", "/api/v1/accounts/1/refresh", "", c, headers)
	if r.Code != 202 {
		t.Fatalf("refresh status %d", r.Code)
	}
	var j domain.Job
	if err := json.Unmarshal(r.Body.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	return j
}
func TestReviewInterruptedRefreshMustExecuteFreshRead(t *testing.T) {
	st, e, p, h, c, headers := reviewFixture(t)
	minute := time.Now().UTC().Format("200601021504")
	first := reviewRefresh(t, h, c, headers)
	e.RunQueuedJobs(t.Context())
	old, err := st.GetJob(t.Context(), first.ID)
	if err != nil || old.Status != "interrupted" {
		t.Fatalf("precondition status=%s err=%v", old.Status, err)
	}
	second := reviewRefresh(t, h, c, headers)
	before := p.trafficCalls
	e.RunQueuedJobs(t.Context())
	done, err := st.GetJob(t.Context(), second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if minute != time.Now().UTC().Format("200601021504") {
		t.Fatal("diagnostic crossed minute; not comparable")
	}
	t.Logf("same_job=%v new_status=%s read_calls_delta=%d controls=%d", second.ID == first.ID, done.Status, p.trafficCalls-before, p.controls)
	if second.ID == first.ID || done.Status != "completed" || p.trafficCalls == before {
		t.Error("promised read-only refresh did not execute a distinct new job")
	}
	if p.controls != 1 {
		t.Error("refresh replayed unknown cloud effect")
	}
}
func TestReviewStaleActionReviewCannotReleaseNewAttempt(t *testing.T) {
	st, e, p, h, c, headers := reviewFixture(t)
	first := reviewRefresh(t, h, c, headers)
	e.RunQueuedJobs(t.Context())
	old, err := st.GetJob(t.Context(), first.ID)
	if err != nil || old.Status != "interrupted" {
		t.Fatalf("precondition %v %v", old, err)
	}
	records := doRequest(t, h, "GET", "/api/v1/recovery", "", c, nil)
	if records.Code != 200 {
		t.Fatal("missing recovery response")
	}
	oldAttempt := reviewActionID(t, h, c)
	actionPath := "/api/v1/recovery/action/" + oldAttempt + "/resolve"
	oldReview := `{"reviewed":true,"note":"checked the original first attempt"}`
	for _, path := range []string{"/api/v1/recovery/job/" + first.ID + "/resolve", actionPath} {
		if r := doRequest(t, h, "POST", path, oldReview, c, headers); r.Code != 200 {
			t.Fatalf("first review %s status=%d", path, r.Code)
		}
	}
	p.fail = false
	second := reviewRefresh(t, h, c, headers)
	e.RunQueuedJobs(t.Context())
	done, err := st.GetJob(t.Context(), second.ID)
	if err != nil || done.Status != "completed" || second.ID == first.ID {
		t.Fatalf("new attempt precondition %v %v", done, err)
	}
	var state string
	st.DB().QueryRow(`SELECT status FROM action_events WHERE event_key='threshold:1:stop'`).Scan(&state)
	if state != "submitted" {
		t.Fatalf("second action=%s", state)
	}
	acc, _ := st.GetAccount(t.Context(), 1)
	wasBlocked, _ := st.AutomationBlocked(t.Context(), 1, store.ActionTarget(acc, "KeepCharging"))
	if !wasBlocked {
		t.Fatal("second attempt not blocked")
	}
	stale := doRequest(t, h, "POST", actionPath, oldReview, c, headers)
	blocked, _ := st.AutomationBlocked(t.Context(), 1, store.ActionTarget(acc, "KeepCharging"))
	t.Logf("distinct_second_job=%v stale_review_status=%d new_attempt_blocked=%v controls=%d", first.ID != second.ID, stale.Code, blocked, p.controls)
	if stale.Code == 200 || !blocked {
		t.Error("old action review resolved a different newer attempt sharing the event key")
	}
}
func TestReviewDailyReportNullAccountMustNotSelectGlobal(t *testing.T) {
	st, _, _, h, c, headers := reviewFixture(t)
	r := doRequest(t, h, "POST", "/api/v1/notifications/daily-report", `{"account_id":null}`, c, headers)
	var count, global, outbox int
	st.DB().QueryRow(`SELECT count(*) FROM jobs`).Scan(&count)
	st.DB().QueryRow(`SELECT count(*) FROM jobs WHERE type='daily_report' AND account_id=0`).Scan(&global)
	st.DB().QueryRow(`SELECT count(*) FROM notification_outbox`).Scan(&outbox)
	t.Logf("status=%d jobs=%d global_report_jobs=%d outbox=%d", r.Code, count, global, outbox)
	if r.Code != 400 || count != 0 || outbox != 0 {
		t.Error("non-integer null account silently became global report")
	}
}

func reviewActionID(t *testing.T, h http.Handler, c []*http.Cookie) string {
	t.Helper()
	response := doRequest(t, h, "GET", "/api/v1/recovery", "", c, nil)
	var body struct {
		Records []store.RecoveryRecord `json:"records"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &body) != nil {
		t.Fatal("recovery read failed")
	}
	for _, r := range body.Records {
		if r.Kind == "action" {
			if r.ID == "" || strings.HasPrefix(r.ID, "threshold:") {
				t.Fatal("reusable attempt identity")
			}
			return r.ID
		}
	}
	t.Fatal("missing pending action")
	return ""
}
func TestReviewConcurrentClientsAndReplacement(t *testing.T) {
	st, e, p, h, c, headers := reviewFixture(t)
	first := reviewRefresh(t, h, c, headers)
	e.RunQueuedJobs(t.Context())
	oldID := reviewActionID(t, h, c)
	if reviewActionID(t, h, c) != oldID {
		t.Fatal("read changed attempt identity")
	}
	path := "/api/v1/recovery/action/" + oldID + "/resolve"
	body := `{"reviewed":true,"note":"first attempt checked"}`
	// Both clients hold the same exact identity. Only one may resolve it.
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); codes <- doRequest(t, h, "POST", path, body, c, headers).Code }()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 200 {
			successes++
		} else if code != 404 {
			t.Fatalf("review response=%d", code)
		}
	}
	if successes != 1 {
		t.Fatal("review was not conditional")
	}
	if r := doRequest(t, h, "POST", "/api/v1/recovery/job/"+first.ID+"/resolve", body, c, headers); r.Code != 200 {
		t.Fatal(r.Code)
	}
	p.fail = false
	// A stale client races creation of another attempt against the same target/key.
	wg.Add(1)
	go func() {
		defer wg.Done()
		if r := doRequest(t, h, "POST", path, body, c, headers); r.Code != 404 {
			t.Errorf("stale race=%d", r.Code)
		}
	}()
	second := reviewRefresh(t, h, c, headers)
	e.RunQueuedJobs(t.Context())
	wg.Wait()
	newID := reviewActionID(t, h, c)
	if oldID == newID {
		t.Fatal("attempt ID reused")
	}
	for _, id := range []string{oldID, "threshold:1:stop"} {
		if r := doRequest(t, h, "POST", "/api/v1/recovery/action/"+id+"/resolve", body, c, headers); r.Code != 404 {
			t.Fatalf("stale/key review accepted=%d", r.Code)
		}
	}
	var status string
	var reviewed int64
	if err := st.DB().QueryRow(`SELECT status,reviewed_at FROM action_events WHERE attempt_id=?`, newID).Scan(&status, &reviewed); err != nil || status != "submitted" || reviewed != 0 {
		t.Fatalf("new attempt changed: %s %d %v", status, reviewed, err)
	}
	var history, audits int
	st.DB().QueryRow(`SELECT count(*) FROM action_events WHERE attempt_id=? AND status='resolved' AND reviewed_at>0`, oldID).Scan(&history)
	st.DB().QueryRow(`SELECT count(*) FROM logs WHERE type='audit' AND message LIKE ?`, "Recovery reviewed action "+oldID+":%").Scan(&audits)
	if history != 1 || audits != 1 || p.controls != 2 || second.ID == first.ID {
		t.Fatalf("history=%d audits=%d controls=%d", history, audits, p.controls)
	}
	t.Logf("old_attempt=%s new_attempt=%s old_review_successes=%d new_status=%s reviewed_at=%d controls=%d", oldID, newID, successes, status, reviewed, p.controls)
}
func TestReviewReadOnlyModeSurvivesReviewBeforeWorker(t *testing.T) {
	st, e, p, h, c, headers := reviewFixture(t)
	// Enable a channel so an accidental notification would produce an outbox row.
	config, err := st.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	config.Notifications.Webhook.Enabled = true
	config.Notifications.Webhook.URL = "http://127.0.0.1:1/never-send"
	if err = st.SaveConfig(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	first := reviewRefresh(t, h, c, headers)
	e.RunQueuedJobs(t.Context())
	oldID := reviewActionID(t, h, c)
	second := reviewRefresh(t, h, c, headers)
	persisted, readErr := st.GetJob(t.Context(), second.ID)
	if readErr != nil || second.ID == first.ID || persisted.Payload != `{"read_only":true}` {
		t.Fatalf("new mode=%+v", second)
	}
	var retained string
	if err = st.DB().QueryRow(`SELECT unique_key FROM jobs WHERE id=?`, first.ID).Scan(&retained); err != nil || retained == "" {
		t.Fatal("old key lost before review")
	}
	body := `{"reviewed":true,"note":"original attempt verified"}`
	for _, path := range []string{"/api/v1/recovery/job/" + first.ID + "/resolve", "/api/v1/recovery/action/" + oldID + "/resolve"} {
		if r := doRequest(t, h, "POST", path, body, c, headers); r.Code != 200 {
			t.Fatal(r.Code)
		}
	}
	p.fail = false
	before := p.trafficCalls
	var outboxBefore int
	st.DB().QueryRow(`SELECT count(*) FROM notification_outbox`).Scan(&outboxBefore)
	e.RunQueuedJobs(t.Context())
	done, err := st.GetJob(t.Context(), second.ID)
	if err != nil || done.Status != "completed" || p.trafficCalls <= before {
		t.Fatalf("new refresh not completed: %+v %v", done, err)
	}
	var outbox int
	st.DB().QueryRow(`SELECT count(*) FROM notification_outbox`).Scan(&outbox)
	account, err := st.GetAccount(t.Context(), 1)
	if err != nil || account.TrafficUsed != 200 || account.InstanceStatus != domain.StatusRunning || account.UpdatedAt.IsZero() {
		t.Fatalf("fresh status not persisted: %+v %v", account, err)
	}
	if p.controls != 1 || outbox != outboxBefore {
		t.Fatalf("read only mutated cloud/notifications: controls=%d outbox=%d before=%d", p.controls, outbox, outboxBefore)
	}
	old, _ := st.GetJob(t.Context(), first.ID)
	if old.Status != "interrupted" {
		t.Fatal("old job history lost")
	}
	t.Logf("old_job=%s new_job=%s mode=%s status=%s new_reads=%d controls=%d outbox_delta=%d", first.ID, second.ID, done.Payload, done.Status, p.trafficCalls-before, p.controls, outbox-outboxBefore)
}
