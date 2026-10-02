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

func TestEnqueueRejectsUnknownJobType(t *testing.T) {
	st, _ := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	_, err := eng.Enqueue(context.Background(), "not_a_job", 0, `{}`, "unknown:enqueue")
	if err == nil || !strings.Contains(err.Error(), "unknown job type") {
		t.Fatalf("err=%v", err)
	}
	var count int
	if err = st.DB().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("unknown job type must not be queued, count=%d", count)
	}
}

func TestEnqueueRejectsNonPositiveAccountID(t *testing.T) {
	st, _ := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	_, err := eng.Enqueue(ctx, JobRefreshAccount, 0, `{}`, "refresh:0")
	if err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("refresh err=%v", err)
	}
	if _, err = eng.Enqueue(ctx, JobTestNotify, 0, ParseNotifyPayload("webhook"), "notify:0"); err != nil {
		t.Fatalf("test notify err=%v", err)
	}
	var count int
	if err = st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("jobs count=%d", count)
	}
}

func TestRunJobRejectsNonPositiveAccountID(t *testing.T) {
	st, _ := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	_, err := eng.runJob(context.Background(), domain.Job{Type: JobRefreshAccount, AccountID: 0, Payload: `{}`})
	if err == nil || !strings.Contains(err.Error(), "account id is invalid") {
		t.Fatalf("err=%v", err)
	}
	if got := provider.controlActions(); len(got) != 0 {
		t.Fatalf("provider calls=%#v", got)
	}
}

func TestProcessJobsUnknownTypeFailsClosed(t *testing.T) {
	st, _ := setupAccount(t, nil)
	defer st.Close()
	provider := newFakeProvider()
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,status,max_attempts,available_at,created_at,updated_at) VALUES('job-unknown','not_a_job',0,'{}','queued',3,unixepoch(),unixepoch(),unixepoch())`); err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err := st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id='job-unknown'`).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(jobErr, "job type is invalid") {
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
	if _, err := st.DB().ExecContext(ctx, `INSERT INTO jobs(id,type,account_id,payload,unique_key,status,max_attempts,available_at,created_at,updated_at) VALUES('control-bad',?,?,'{','control-bad','queued',3,unixepoch(),unixepoch(),unixepoch())`, JobControlInstance, account.ID); err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var status, jobErr string
	if err := st.DB().QueryRowContext(ctx, `SELECT status,error FROM jobs WHERE id='control-bad'`).Scan(&status, &jobErr); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(jobErr, "payload is invalid") {
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
	logger, logs := capturingLogger()
	eng := New(st, provider, notify.New(), logger, 1)
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
	if strings.Contains(logs.String(), "ecs-secret-should-not-leak") {
		t.Fatalf("job panic leaked into slog: %s", logs.String())
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

func TestProcessJobsPersistsRedactedNotifySecrets(t *testing.T) {
	const token = "123456:AA-secret-token-value"
	st, account := setupAccount(t, func(config *domain.Config) {
		config.Notifications.Telegram.Token = token
	})
	defer st.Close()
	provider := newFakeProvider()
	provider.controlErr = errors.New("ecs denied " + token)
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), JobUniqueKey(JobControlInstance, account.ID, "persist-redact"))
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT error FROM jobs WHERE id=?`, job.ID).Scan(&jobErr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jobErr, token) {
		t.Fatalf("persisted job error leaked telegram token: %q", jobErr)
	}
	if !strings.Contains(jobErr, "[redacted]") {
		t.Fatalf("persisted job error missing redaction: %q", jobErr)
	}
}

func TestAddLogPersistsRedactedNotifyAndAccountSecrets(t *testing.T) {
	const token = "123456:AA-secret-token-value"
	const ak = "ak-secret-value-xyz"
	st, _ := setupAccount(t, func(config *domain.Config) {
		config.Accounts[0].AccessKeySecret = ak
		config.Notifications.Telegram.Token = token
	})
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	msg := `Post "https://api.telegram.org/bot` + token + `/sendMessage": denied ` + ak
	if err := eng.addLog(ctx, "error", msg); err != nil {
		t.Fatal(err)
	}
	logs, err := st.ListLogs(ctx, "action", 10)
	if err != nil || len(logs) == 0 {
		t.Fatalf("logs=%#v err=%v", logs, err)
	}
	got := logs[0].Message
	if strings.Contains(got, token) || strings.Contains(got, ak) {
		t.Fatalf("persisted log leaked secrets: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("persisted log missing redaction: %q", got)
	}
}

func TestProcessJobsPersistsRedactedAccountSecret(t *testing.T) {
	const ak = "ak-secret-value-xyz"
	st, account := setupAccount(t, func(config *domain.Config) {
		config.Accounts[0].AccessKeySecret = ak
	})
	defer st.Close()
	provider := newFakeProvider()
	provider.controlErr = errors.New("ecs denied " + ak)
	eng := New(st, provider, notify.New(), quietLogger(), 1)
	ctx := context.Background()
	job, err := eng.Enqueue(ctx, JobControlInstance, account.ID, ParseControlPayload("start", "手动"), JobUniqueKey(JobControlInstance, account.ID, "persist-ak"))
	if err != nil {
		t.Fatal(err)
	}
	eng.processJobs(ctx, 0)
	var jobErr string
	if err = st.DB().QueryRowContext(ctx, `SELECT error FROM jobs WHERE id=?`, job.ID).Scan(&jobErr); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(jobErr, ak) {
		t.Fatalf("persisted job error leaked account secret: %q", jobErr)
	}
	if !strings.Contains(jobErr, "[redacted]") {
		t.Fatalf("persisted job error missing redaction: %q", jobErr)
	}
}
