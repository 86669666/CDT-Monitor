package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/store"
)

func TestCoreHTTPConcurrentSetupDoesNotReplaceWinnerSession(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := testAPIHandler(t, st)
	bodies := []string{`{"admin_password":"Setup-Alpha-password","traffic_threshold":91,"accounts":[]}`, `{"admin_password":"Setup-Beta-password","traffic_threshold":72,"accounts":[]}`}
	start := make(chan struct{})
	var wg sync.WaitGroup
	responses := make([]*httptest.ResponseRecorder, 2)
	for i := range bodies {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			responses[i] = doRequest(t, h, "POST", "/api/v1/setup", bodies[i], nil, nil)
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, r := range responses {
		switch r.Code {
		case 201:
			if winner != -1 {
				t.Fatal("multiple HTTP winners")
			}
			winner = i
		case 409:
			if len(r.Result().Cookies()) != 0 {
				t.Fatal("loser created auth cookies")
			}
		default:
			t.Fatalf("unexpected setup status %d", r.Code)
		}
	}
	if winner < 0 {
		t.Fatal("missing winner")
	}
	cookies := responses[winner].Result().Cookies()
	valid := doRequest(t, h, "GET", "/api/v1/config", "", cookies, nil)
	if valid.Code != 200 {
		t.Fatal("loser revoked winner session")
	}
	var count int
	st.DB().QueryRow(`SELECT count(*) FROM sessions`).Scan(&count)
	if count != 1 {
		t.Fatalf("session count=%d", count)
	}
}

func TestCoreHTTPConfigCannotChangePasswordAndInvalidConfigIsAtomic(t *testing.T) {
	st := initializedAuthStore(t)
	h := testAPIHandler(t, st)
	session, csrf := loginCookies(t, h)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	original := doRequest(t, h, "GET", "/api/v1/config", "", cookies, nil).Body.String()
	var config map[string]any
	json.Unmarshal([]byte(original), &config)
	config["admin_password"] = "Bypass-new-password"
	config["traffic_threshold"] = 45
	body, _ := json.Marshal(config)
	r := doRequest(t, h, "PUT", "/api/v1/config", string(body), cookies, headers)
	if r.Code != 400 {
		t.Fatalf("password bypass status %d", r.Code)
	}
	after := doRequest(t, h, "GET", "/api/v1/config", "", cookies, nil)
	if after.Body.String() != original {
		t.Fatal("rejected password changed config or session")
	}
	ok, err := st.VerifyAdminPassword(t.Context(), testAdminPassword)
	if err != nil || !ok {
		t.Fatal("old password lost")
	}
	ok, _ = st.VerifyAdminPassword(t.Context(), "Bypass-new-password")
	if ok {
		t.Fatal("bypass password accepted")
	}
	for _, path := range []string{"/api/v1/config", "/api/v1/accounts/1/settings"} {
		method := "PUT"
		payload := map[string]any{}
		if path == "/api/v1/config" {
			json.Unmarshal([]byte(original), &payload)
			payload["daily_report_time"] = "25:00"
		} else {
			method = "PATCH"
			payload["daily_report_time"] = "25:00"
		}
		body, _ := json.Marshal(payload)
		if doRequest(t, h, method, path, string(body), cookies, headers).Code != 400 {
			t.Fatal("bad clock accepted")
		}
		if doRequest(t, h, "GET", "/api/v1/config", "", cookies, nil).Body.String() != original {
			t.Fatal("bad clock partially saved")
		}
	}
	for _, current := range []string{"", "wrong-password"} {
		body, _ := json.Marshal(map[string]string{"current_password": current, "new_password": "Replacement-password"})
		if doRequest(t, h, "PUT", "/api/v1/admin/password", string(body), cookies, headers).Code != 401 {
			t.Fatal("missing/wrong current password accepted")
		}
	}
}

func TestCoreHTTPDailyReportInputMatrixHasNoPartialJobs(t *testing.T) {
	st := initializedAuthStore(t)
	h := testAPIHandler(t, st)
	session, csrf := loginCookies(t, h)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	for _, body := range []string{"", "null", "[]", "1", `{"account_id":`, `{"account_id":-1}`, `{"account_id":null}`, `{"account_id":1.5}`, `{"account_id":9223372036854775808}`, `{"account_id":1,"extra":true}`, `{} {}`, `{}]`, `{"account_id":999}`} {
		r := doRequest(t, h, "POST", "/api/v1/notifications/daily-report", body, cookies, headers)
		want := 400
		if strings.Contains(body, "999") {
			want = 404
		}
		if r.Code != want {
			t.Errorf("input %q status=%d", body, r.Code)
		}
	}
	var jobs, outbox int
	st.DB().QueryRow(`SELECT count(*) FROM jobs`).Scan(&jobs)
	st.DB().QueryRow(`SELECT count(*) FROM notification_outbox`).Scan(&outbox)
	if jobs != 0 || outbox != 0 {
		t.Fatal("invalid report created partial work")
	}
	for _, body := range []string{`{}`, `{"account_id":0}`, `{"account_id":1}`} {
		if r := doRequest(t, h, "POST", "/api/v1/notifications/daily-report", body, cookies, headers); r.Code != 202 {
			t.Fatalf("valid body rejected %q status=%d", body, r.Code)
		}
	}
}

func TestCoreHTTPStatusETagCoversExactRepresentation(t *testing.T) {
	st := initializedAuthStore(t)
	h := testAPIHandler(t, st)
	session, _ := loginCookies(t, h)
	cookies := []*http.Cookie{session}
	fetch := func(tag string) *httptest.ResponseRecorder {
		return doRequest(t, h, "GET", "/api/v1/status", "", cookies, map[string]string{"If-None-Match": tag})
	}
	first := fetch("")
	if first.Code != 200 {
		t.Fatal(first.Code)
	}
	tag := first.Header().Get("ETag")
	want := fmt.Sprintf(`"%x"`, sha256.Sum256(first.Body.Bytes()))
	if tag != want {
		t.Fatal("ETag not computed over actual response bytes")
	}
	for _, condition := range []string{tag, "W/" + tag, `"other", W/` + tag, "*"} {
		r := fetch(condition)
		if r.Code != 304 || r.Body.Len() != 0 || r.Header().Get("ETag") != tag || r.Header().Get("Cache-Control") != "private, max-age=15" {
			t.Fatal("conditional representation headers wrong")
		}
	}
	if _, err := st.DB().Exec(`UPDATE settings SET value='true' WHERE key='enable_billing'`); err != nil {
		t.Fatal(err)
	}
	mutations := []func() error{
		func() error {
			return st.SetBillingCache(t.Context(), 1, "balance", "", map[string]any{"amount": 123.45, "currency": "CNY"})
		},
		func() error {
			_, e := st.DB().Exec(`UPDATE accounts SET traffic_used=7,updated_at=? WHERE id=1`, time.Now().Unix())
			return e
		},
		func() error {
			_, e := st.DB().Exec(`UPDATE accounts SET instance_status='Stopped' WHERE id=1`)
			return e
		},
		func() error { _, e := st.DB().Exec(`UPDATE accounts SET remark='Changed' WHERE id=1`); return e },
		func() error {
			_, e := st.DB().Exec(`UPDATE settings SET value='70' WHERE key='traffic_threshold'`)
			return e
		},
		func() error {
			_, e := st.DB().Exec(`UPDATE accounts SET updated_at=? WHERE id=1`, time.Now().Add(-2*time.Hour).Unix())
			return e
		},
	}
	for _, mutate := range mutations {
		if err := mutate(); err != nil {
			t.Fatal(err)
		}
		r := fetch(tag)
		if r.Code != 200 || r.Header().Get("ETag") == tag {
			t.Fatal("changed representation returned stale validator")
		}
		tag = r.Header().Get("ETag")
		if tag != fmt.Sprintf(`"%x"`, sha256.Sum256(r.Body.Bytes())) {
			t.Fatal("changed byte hash mismatch")
		}
	}
	if r := doRequest(t, h, "GET", "/api/v1/status", "", nil, map[string]string{"If-None-Match": "*"}); r.Code != 401 {
		t.Fatal("conditional request bypassed auth")
	}
}

func TestCoreHTTPStatusETagChangesAtStaleBoundaryWithoutDBWrite(t *testing.T) {
	st := initializedAuthStore(t)
	h := testAPIHandler(t, st)
	session, _ := loginCookies(t, h)
	cookies := []*http.Cookie{session}
	if _, err := st.DB().Exec(`UPDATE settings SET value='30' WHERE key='api_interval'; UPDATE accounts SET updated_at=? WHERE id=1`, time.Now().Unix()-179); err != nil {
		t.Fatal(err)
	}
	first := doRequest(t, h, "GET", "/api/v1/status", "", cookies, nil)
	if first.Code != 200 || !strings.Contains(first.Body.String(), `"stale":false`) {
		t.Fatal("fresh boundary precondition")
	}
	tag := first.Header().Get("ETag")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		next := doRequest(t, h, "GET", "/api/v1/status", "", cookies, map[string]string{"If-None-Match": tag})
		if next.Code == 200 {
			if next.Header().Get("ETag") == tag || !strings.Contains(next.Body.String(), `"stale":true`) {
				t.Fatal("stale representation not changed")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("stale boundary retained old validator")
}

func TestCoreHTTPRecoveryRequiresSessionCSRFAndExplicitSingleReview(t *testing.T) {
	st := initializedAuthStore(t)
	h := testAPIHandler(t, st)
	session, csrf := loginCookies(t, h)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	ids := []string{}
	for i := 0; i < 2; i++ {
		job, err := st.EnqueueJob(t.Context(), "refresh_account", 1, `{}`, fmt.Sprintf("unknown:%d", i), 3)
		if err != nil {
			t.Fatal(err)
		}
		st.DB().Exec(`UPDATE jobs SET status='interrupted',error='outcome_unknown',attempts=1 WHERE id=?`, job.ID)
		ids = append(ids, job.ID)
	}
	path := "/api/v1/recovery/job/" + ids[0] + "/resolve"
	body := `{"reviewed":true,"note":"verified original target"}`
	if doRequest(t, h, "POST", path, body, nil, nil).Code != 401 {
		t.Fatal("anonymous review accepted")
	}
	if doRequest(t, h, "POST", path, body, cookies, nil).Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	_, key, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read", "instance:control"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if doRequest(t, h, "POST", path, body, nil, map[string]string{"Authorization": "Bearer " + key}).Code != 403 {
		t.Fatal("API key review accepted")
	}
	if doRequest(t, h, "POST", path, `{"note":"not explicit"}`, cookies, headers).Code != 400 {
		t.Fatal("implicit review accepted")
	}
	if doRequest(t, h, "POST", path, body, cookies, headers).Code != 200 {
		t.Fatal("explicit review failed")
	}
	var first, second int
	st.DB().QueryRow(`SELECT reviewed_at FROM jobs WHERE id=?`, ids[0]).Scan(&first)
	st.DB().QueryRow(`SELECT reviewed_at FROM jobs WHERE id=?`, ids[1]).Scan(&second)
	if first == 0 || second != 0 {
		t.Fatal("review did not target single record")
	}
	for _, id := range ids {
		got, err := st.GetJob(context.Background(), id)
		if err != nil || got.Status != "interrupted" || got.Attempts != 1 {
			t.Fatal("review replayed job")
		}
	}
}
