package engine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestProcessJobsCompletesRefreshFromFakeAliyun(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.traffic = 9.25
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err := eng.Enqueue(ctx, JobRefreshAccount, account.ID, `{}`, JobUniqueKey(JobRefreshAccount, account.ID, "test")); err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	updated, err := st.GetAccount(ctx, account.ID)
	if err != nil || updated.TrafficUsed != 9.25 {
		t.Fatalf("account = %#v err=%v", updated, err)
	}
	var status string
	if err = st.DB().QueryRowContext(ctx, `SELECT status FROM jobs WHERE account_id=?`, account.ID).Scan(&status); err != nil || status != "completed" {
		t.Fatalf("job status = %q err=%v", status, err)
	}
}

func TestProcessJobsRequeuesFailedControl(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.controlErr = errors.New("ecs unavailable")
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), JobUniqueKey(JobControlInstance, account.ID, "start"))
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || jobErr == "" {
		t.Fatalf("failed control status=%q error=%q", status, jobErr)
	}
	if got := provider.controlActions(); len(got) != 1 || got[0] != "start" {
		t.Fatalf("controls = %#v", got)
	}
}

func TestProcessJobsUnknownTypeRequeues(t *testing.T) {
	st, _ := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := st.EnqueueJob(ctx, "not_a_job", 0, `{}`, "unknown:1", 3)
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || !strings.Contains(jobErr, "unknown job type") {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("unknown job must not call Aliyun, controls=%#v", got)
	}
}

func TestProcessJobsTestNotificationSendsWebhook(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	st, _ := setupAccount(t, func(config *domain.Config) {
		config.Notifications.Webhook.Enabled = true
		config.Notifications.Webhook.URL = server.URL
		config.Notifications.Webhook.Method = "POST"
		config.Notifications.Webhook.Type = "JSON"
	})
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobTestNotify, 0, ParseNotifyPayload("webhook"), "")
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	if hits != 1 {
		t.Fatalf("webhook hits = %d", hits)
	}
	var status string
	if err = st.DB().QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, job.ID).Scan(&status); err != nil || status != "completed" {
		t.Fatalf("job status = %q err=%v", status, err)
	}
}

func TestProcessJobsInvalidControlPayloadRequeues(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := st.EnqueueJob(ctx, JobControlInstance, account.ID, `{`, "control-bad", 3)
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || jobErr == "" {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("invalid payload must not call Aliyun, controls=%#v", got)
	}
}

func TestProcessJobsUnknownNotifyChannelRequeues(t *testing.T) {
	st, _ := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobTestNotify, 0, ParseNotifyPayload("sms"), "notify-sms")
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || !strings.Contains(jobErr, "unsupported notification channel") {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
}

func TestProcessJobsFailedWebhookTestNotifyRequeues(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer server.Close()
	st, _ := setupAccount(t, func(config *domain.Config) {
		config.Notifications.Webhook.Enabled = true
		config.Notifications.Webhook.URL = server.URL
		config.Notifications.Webhook.Method = "POST"
		config.Notifications.Webhook.Type = "JSON"
	})
	defer st.Close()
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobTestNotify, 0, ParseNotifyPayload("webhook"), "notify-fail")
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || !strings.Contains(jobErr, "webhook HTTP 502") {
		t.Fatalf("status=%q error=%q", status, jobErr)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("notify test must not call Aliyun, controls=%#v", got)
	}
}

func TestProcessJobsRecoversFromControlPanic(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.controlPanic = "ecs-secret-should-not-leak"
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), JobUniqueKey(JobControlInstance, account.ID, "start"))
	if err != nil {
		t.Fatal(err)
	}
	refresh, err := eng.Enqueue(ctx, JobRefreshAccount, account.ID, `{}`, JobUniqueKey(JobRefreshAccount, account.ID, "panic-followup"))
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || jobErr != errJobPanic.Error() {
		t.Fatalf("panicked control status=%q error=%q", status, jobErr)
	}
	if strings.Contains(jobErr, "ecs-secret-should-not-leak") {
		t.Fatalf("job error leaked panic: %q", jobErr)
	}
	var refreshStatus string
	if err = st.DB().QueryRowContext(ctx, `SELECT status FROM jobs WHERE id=?`, refresh.ID).Scan(&refreshStatus); err != nil || refreshStatus != "completed" {
		t.Fatalf("follow-up refresh status=%q err=%v", refreshStatus, err)
	}
}

func TestProcessJobsControlErrorRedactsAccessKeyMaterial(t *testing.T) {
	st, account := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	provider.controlErr = errors.New("ecs denied secret for LTAItest")
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), JobUniqueKey(JobControlInstance, account.ID, "start"))
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || jobErr == "" {
		t.Fatalf("failed control status=%q error=%q", status, jobErr)
	}
	if strings.Contains(jobErr, "secret") || strings.Contains(jobErr, "LTAItest") {
		t.Fatalf("job error leaked material: %q", jobErr)
	}
	if !strings.Contains(jobErr, "[redacted]") || !strings.Contains(jobErr, "LTAItes***") {
		t.Fatalf("job error was not redacted: %q", jobErr)
	}
}

func TestProcessJobsNotifyErrorRedactsTelegramToken(t *testing.T) {
	const token = "123456:AA-secret-token-value"
	st, _ := setupAccount(t, func(config *domain.Config) {
		config.Notifications.Telegram.Enabled = true
		config.Notifications.Telegram.Token = token
		config.Notifications.Telegram.ChatID = "42"
		config.Notifications.Telegram.ProxyType = "custom"
		config.Notifications.Telegram.ProxyURL = "http://127.0.0.1:1"
	})
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobTestNotify, 0, ParseNotifyPayload("telegram"), "notify-telegram")
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id=?`, job.ID).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || jobErr == "" {
		t.Fatalf("failed notify status=%q error=%q", status, jobErr)
	}
	if strings.Contains(jobErr, token) || strings.Contains(jobErr, "AA-secret-token-value") {
		t.Fatalf("job error leaked telegram token: %q", jobErr)
	}
}
