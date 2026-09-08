package engine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/notify"
)

func TestFlushOutboxSendsWebhookThenCompletes(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "threshold") && r.URL.Query().Get("title") == "" && r.URL.Query().Get("message") == "" {
			t.Errorf("unexpected webhook payload path=%s body=%s", r.URL.RawQuery, body)
		}
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
	event := domain.NotificationEvent{ID: "evt-ok", Type: "threshold", Title: "流量阈值告警", Summary: "test", Fields: map[string]string{"k": "v"}}
	if err := st.AddOutbox(ctx, event, []string{"webhook"}); err != nil {
		t.Fatal(err)
	}
	eng.flushOutbox(ctx)
	if hits != 1 {
		t.Fatalf("webhook hits = %d", hits)
	}
	var status string
	if err := st.DB().QueryRowContext(ctx, `SELECT status FROM notification_outbox WHERE event_id='evt-ok'`).Scan(&status); err != nil || status != "sent" {
		t.Fatalf("outbox status = %q err=%v", status, err)
	}
}

func TestFlushOutboxRetriesFailedWebhook(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("upstream down"))
	}))
	defer server.Close()

	st, _ := setupAccount(t, func(config *domain.Config) {
		config.Notifications.Webhook.Enabled = true
		config.Notifications.Webhook.URL = server.URL
		config.Notifications.Webhook.Method = "POST"
	})
	defer st.Close()
	eng := New(st, newFakeProvider(), notify.New(), quietLogger(), 1)
	ctx := context.Background()
	event := domain.NotificationEvent{ID: "evt-fail", Type: "threshold", Title: "t", Summary: "s"}
	if err := st.AddOutbox(ctx, event, []string{"webhook"}); err != nil {
		t.Fatal(err)
	}
	eng.flushOutbox(ctx)
	var status, lastError string
	if err := st.DB().QueryRowContext(ctx, `SELECT status,last_error FROM notification_outbox WHERE event_id='evt-fail'`).Scan(&status, &lastError); err != nil {
		t.Fatal(err)
	}
	if status != "queued" || !strings.Contains(lastError, "webhook HTTP 502") {
		t.Fatalf("status=%q last_error=%q", status, lastError)
	}
	if strings.Contains(strings.ToLower(lastError), "secret") {
		t.Fatalf("outbox error leaked secret: %q", lastError)
	}
}

func TestFlushOutboxRecoversFromNotifierPanic(t *testing.T) {
	st, _ := setupAccount(t, nil)
	defer st.Close()
	eng := New(st, newFakeProvider(), nil, quietLogger(), 1)
	ctx := context.Background()
	if err := st.AddOutbox(ctx, domain.NotificationEvent{ID: "evt-panic-1", Type: "threshold", Title: "t", Summary: "s"}, []string{"webhook"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddOutbox(ctx, domain.NotificationEvent{ID: "evt-panic-2", Type: "threshold", Title: "t", Summary: "s"}, []string{"webhook"}); err != nil {
		t.Fatal(err)
	}
	eng.flushOutbox(ctx)
	var count int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM notification_outbox WHERE status='queued' AND last_error=?`, errJobPanic.Error()).Scan(&count); err != nil || count != 2 {
		t.Fatalf("recovered outbox count=%d err=%v", count, err)
	}
	var lastError string
	if err := st.DB().QueryRowContext(ctx, `SELECT last_error FROM notification_outbox WHERE event_id='evt-panic-1'`).Scan(&lastError); err != nil {
		t.Fatal(err)
	}
	if lastError != errJobPanic.Error() || strings.Contains(lastError, "nil pointer") || strings.Contains(lastError, "runtime") {
		t.Fatalf("outbox panic leaked internals: %q", lastError)
	}
}
