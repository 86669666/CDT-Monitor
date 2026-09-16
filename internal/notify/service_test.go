package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wang4386/CDT-Monitor/internal/domain"
)

func TestReplacementsExposeWebhookVariables(t *testing.T) {
	event := domain.NotificationEvent{
		Type:      "threshold",
		Title:     "流量阈值告警",
		Summary:   "即将达到阈值",
		AccountID: 42,
		Fields: map[string]string{
			"当前流量": "12.3456 GB",
			"设定阈值": "95%",
			"实例":   "i-test",
			"实例状态": "Running",
		},
		CreatedAt: time.Date(2026, 7, 23, 8, 9, 10, 0, time.FixedZone("CST", 8*60*60)),
	}
	values := replacements(event)
	for key, want := range map[string]string{
		"#TITLE#": "流量阈值告警", "#MSG#": "即将达到阈值", "#ACCOUNT#": "42", "#ACCOUNT_ID#": "42",
		"#TRAFFIC#": "12.3456", "#MAX_TRAFFIC#": "95", "#INSTANCE#": "i-test", "#STATUS#": "Running", "#TYPE#": "threshold",
	} {
		if values[key] != want {
			t.Fatalf("%s = %q, want %q", key, values[key], want)
		}
	}
	if values["#CREATED_AT#"] != "2026-07-23T00:09:10Z" {
		t.Fatalf("#CREATED_AT# = %q", values["#CREATED_AT#"])
	}
}

func TestDingTalkWebhookAddsSignature(t *testing.T) {
	var timestamp, signature string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timestamp = r.URL.Query().Get("timestamp")
		signature = r.URL.Query().Get("sign")
		if timestamp == "" || signature == "" {
			t.Error("DingTalk signature query parameters are missing")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	service := New()
	service.httpClient = server.Client()
	secret := "SEC-test"
	err := service.sendWebhook(context.Background(), domain.WebhookConfig{
		Enabled: true, Provider: "dingtalk", Secret: secret, URL: server.URL, Method: "POST", Type: "JSON",
		Body: `{"msgtype":"text","text":{"content":"#MSG#"}}`,
	}, domain.NotificationEvent{Title: "标题", Summary: "消息", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := strconv.ParseInt(timestamp, 10, 64); err != nil {
		t.Fatalf("invalid timestamp %q: %v", timestamp, err)
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(timestamp + "\n" + secret))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if signature != want {
		t.Fatalf("signature = %q, want %q", signature, want)
	}
}

func TestReplaceTemplateJSONAndForm(t *testing.T) {
	replacements := map[string]string{"#MSG#": "hello world", "#TITLE#": "通知"}
	if got := replaceTemplate("msg=#MSG#", replacements, true); got != "msg=hello+world" {
		t.Fatalf("form replacement = %q", got)
	}
	if got := replaceTemplate(`{"message":"#MSG#"}`, replacements, false); got != `{"message":"hello world"}` {
		t.Fatalf("json replacement = %q", got)
	}
}

func TestSanitizeNotificationErrorRedactsTelegramToken(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	err := sanitizeNotificationError(errors.New(`Post "https://api.telegram.org/bot123456:AA-secret-token-value/sendMessage": connection refused`), config)
	if err == nil {
		t.Fatal("expected redacted error")
	}
	msg := err.Error()
	if strings.Contains(msg, "AA-secret-token-value") || strings.Contains(msg, "123456:AA") {
		t.Fatalf("telegram token leaked: %q", msg)
	}
	if !strings.Contains(msg, "[redacted]") {
		t.Fatalf("expected redaction marker in %q", msg)
	}
}

func TestSanitizeNotificationErrorRedactsWebhookURLAndSecret(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Webhook.URL = "http://127.0.0.1:1/hooks/super-webhook-secret"
	config.Notifications.Webhook.Secret = "ding-secret-value"
	config.Notifications.Webhook.Body = `{"access_token":"body-token-value"}`
	err := sanitizeNotificationError(errors.New(`Post "http://127.0.0.1:1/hooks/super-webhook-secret?sign=ding-secret-value" body={"access_token":"body-token-value"}: connection refused`), config)
	if err == nil {
		t.Fatal("expected redacted error")
	}
	msg := err.Error()
	if strings.Contains(msg, "super-webhook-secret") || strings.Contains(msg, "ding-secret-value") || strings.Contains(msg, "body-token-value") {
		t.Fatalf("webhook secret leaked: %q", msg)
	}
	if !strings.Contains(msg, "[redacted]") {
		t.Fatalf("expected redaction marker in %q", msg)
	}
}

func TestSendTelegramRedactsTokenFromTransportError(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.Enabled = true
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	config.Notifications.Telegram.ChatID = "42"
	config.Notifications.Telegram.ProxyType = "custom"
	config.Notifications.Telegram.ProxyURL = "http://127.0.0.1:1"
	err := New().Send(context.Background(), "telegram", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if err == nil {
		t.Fatal("expected telegram transport error")
	}
	msg := err.Error()
	if strings.Contains(msg, "AA-secret-token-value") {
		t.Fatalf("telegram token leaked from Send: %q", msg)
	}
}

func TestRedactSecretsLeavesEmptyAndUnknownText(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	if got := RedactSecrets("", config); got != "" {
		t.Fatalf("empty = %q", got)
	}
	msg := `Post "https://api.telegram.org/bot123456:AA-secret-token-value/sendMessage": connection refused`
	got := RedactSecrets(msg, config)
	if strings.Contains(got, "AA-secret-token-value") {
		t.Fatalf("token leaked: %q", got)
	}
	if !strings.Contains(got, "[redacted]") {
		t.Fatalf("expected redaction in %q", got)
	}
}

func TestRedactSecretsIncludesAccountSecrets(t *testing.T) {
	config := domain.Config{
		Accounts: []domain.Account{{AccessKeySecret: "ak-secret-from-config"}},
	}
	msg := "ecs denied ak-secret-from-config and extra-ak-secret-value"
	got := RedactSecrets(msg, config, "extra-ak-secret-value")
	if strings.Contains(got, "ak-secret-from-config") || strings.Contains(got, "extra-ak-secret-value") {
		t.Fatalf("account secret leaked: %q", got)
	}
	if strings.Count(got, "[redacted]") != 2 {
		t.Fatalf("expected both secrets redacted: %q", got)
	}
}

func TestValidateCallbackURLRejectsMetadataAndNonHTTP(t *testing.T) {
	allowed := []string{
		"",
		domain.ClearSecretSentinel,
		"https://oapi.dingtalk.com/robot/send?access_token=x",
		"http://127.0.0.1:1/hooks/test",
		"http://192.168.1.10/hook",
		"https://example.test/hook?access_token=#TOKEN#",
	}
	for _, raw := range allowed {
		if err := ValidateCallbackURL(raw); err != nil {
			t.Fatalf("allowed %q: %v", raw, err)
		}
	}
	if err := ValidateCallbackURL("socks5://127.0.0.1:1080"); !errors.Is(err, errUnsupportedNotifyScheme) {
		t.Fatalf("webhook socks URL err=%v", err)
	}
	if err := ValidateProxyURL("socks5://user:proxy-pass-value@127.0.0.1:1080"); err != nil {
		t.Fatalf("socks proxy URL rejected: %v", err)
	}
	if err := ValidateProxyURL("socks5://100.100.100.200:1080"); !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("metadata socks proxy err=%v", err)
	}
	blocked := map[string]error{
		"file:///etc/passwd":                        errUnsupportedNotifyScheme,
		"gopher://127.0.0.1/":                       errUnsupportedNotifyScheme,
		"http://169.254.169.254/latest/meta-data/":  errForbiddenNotifyHost,
		"https://100.100.100.200/latest/meta-data/": errForbiddenNotifyHost,
		"http://metadata.google.internal/":          errForbiddenNotifyHost,
		"http://[fd00:ec2::254]/latest/meta-data/":  errForbiddenNotifyHost,
	}
	for raw, want := range blocked {
		if err := ValidateCallbackURL(raw); !errors.Is(err, want) {
			t.Fatalf("%q err=%v want %v", raw, err, want)
		}
	}
	if err := ValidateDialHost("100.100.100.200"); !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("dial host err=%v", err)
	}
	if err := ValidateDialHost("192.168.1.1"); err != nil {
		t.Fatalf("lan dial host rejected: %v", err)
	}
}

func TestSendRejectsMetadataWebhookURL(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Webhook.Enabled = true
	config.Notifications.Webhook.URL = "http://100.100.100.200/latest/meta-data/"
	config.Notifications.Webhook.Method = "POST"
	config.Notifications.Webhook.Type = "JSON"
	err := New().Send(context.Background(), "webhook", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("send err=%v", err)
	}
}

func TestSendTelegramRejectsMetadataProxyURL(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.Enabled = true
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	config.Notifications.Telegram.ChatID = "42"
	config.Notifications.Telegram.ProxyType = "custom"
	config.Notifications.Telegram.ProxyURL = "http://169.254.169.254"
	err := New().Send(context.Background(), "telegram", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("send err=%v", err)
	}
}
