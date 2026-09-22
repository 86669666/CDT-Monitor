package notify

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
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

func TestRedactSecretsIncludesTelegramChatIDAndProxyUser(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.ChatID = "tg-chat-id-value"
	config.Notifications.Telegram.ProxyUser = "socks-user-value"
	msg := "telegram chat tg-chat-id-value via socks-user-value failed"
	got := RedactSecrets(msg, config)
	if strings.Contains(got, "tg-chat-id-value") || strings.Contains(got, "socks-user-value") {
		t.Fatalf("telegram identity leaked: %q", got)
	}
	if strings.Count(got, "[redacted]") != 2 {
		t.Fatalf("expected both identities redacted: %q", got)
	}
	if got := RedactSecrets("chat 42 ok", domain.Config{Notifications: domain.NotificationConfig{Telegram: domain.TelegramConfig{ChatID: "42"}}}); got != "chat 42 ok" {
		t.Fatalf("short chat id should not redact: %q", got)
	}
}

func TestRedactSecretsIncludesEmailIdentities(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Email.Username = "monitor@example.test"
	config.Notifications.Email.To = "ops-alerts@example.test"
	msg := "smtp AUTH failed for monitor@example.test sending to ops-alerts@example.test"
	got := RedactSecrets(msg, config)
	if strings.Contains(got, "monitor@example.test") || strings.Contains(got, "ops-alerts@example.test") {
		t.Fatalf("email identity leaked: %q", got)
	}
	if strings.Count(got, "[redacted]") != 2 {
		t.Fatalf("expected both identities redacted: %q", got)
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
		"http://0.0.0.0/hooks/test":                 errForbiddenNotifyHost,
		"http://[::]/hooks/test":                    errForbiddenNotifyHost,
		"http://224.0.0.1/hooks/test":               errForbiddenNotifyHost,
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
	if err := ValidateDialHost("0.0.0.0"); !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("unspecified dial host err=%v", err)
	}
	if err := ValidateDialHost("224.0.0.1"); !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("multicast dial host err=%v", err)
	}
	if err := ValidateDialHost(strings.Repeat("a", maxDialHostRunes+1)); !errors.Is(err, errInvalidNotifyIdentity) {
		t.Fatalf("oversized dial host err=%v", err)
	}
	if err := ValidateCallbackURL("https://example.test/" + strings.Repeat("x", maxNotifyURLRunes)); !errors.Is(err, errInvalidNotifyPayload) {
		t.Fatalf("oversized webhook URL err=%v", err)
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

func TestSendWebhookDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	config := domain.Config{}
	config.Notifications.Webhook.Enabled = true
	config.Notifications.Webhook.URL = source.URL
	config.Notifications.Webhook.Method = "POST"
	config.Notifications.Webhook.Type = "JSON"
	err := New().Send(context.Background(), "webhook", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errNotifyRedirect) {
		t.Fatalf("send err=%v", err)
	}
	if hit {
		t.Fatal("webhook send followed a redirect")
	}
}

func TestSendWebhookRejectsHostnameResolvedToMetadata(t *testing.T) {
	original := lookupNotifyIPs
	lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "metadata.example.test" {
			return []net.IP{net.ParseIP("100.100.100.200")}, nil
		}
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	}
	t.Cleanup(func() { lookupNotifyIPs = original })

	config := domain.Config{}
	config.Notifications.Webhook.Enabled = true
	config.Notifications.Webhook.URL = "http://metadata.example.test/hooks/test"
	config.Notifications.Webhook.Method = "POST"
	config.Notifications.Webhook.Type = "JSON"
	err := New().Send(context.Background(), "webhook", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("send err=%v", err)
	}
}

func TestSendTelegramRejectsProxyHostnameResolvedToMetadata(t *testing.T) {
	original := lookupNotifyIPs
	lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "tg-proxy.example.test" {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	}
	t.Cleanup(func() { lookupNotifyIPs = original })

	config := domain.Config{}
	config.Notifications.Telegram.Enabled = true
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	config.Notifications.Telegram.ChatID = "42"
	config.Notifications.Telegram.ProxyType = "custom"
	config.Notifications.Telegram.ProxyURL = "http://tg-proxy.example.test"
	err := New().Send(context.Background(), "telegram", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("send err=%v", err)
	}
}

func TestValidateNotifyOptionsRejectsUnknownValues(t *testing.T) {
	config := domain.NotificationConfig{}
	if err := ValidateNotifyOptions(config); err != nil {
		t.Fatalf("empty options err=%v", err)
	}
	config.Email.Security = "ssl"
	config.Telegram.ProxyType = "socks5"
	config.Webhook.Method = "POST"
	config.Webhook.Type = "FORM"
	config.Webhook.Provider = "dingtalk"
	if err := ValidateNotifyOptions(config); err != nil {
		t.Fatalf("known options err=%v", err)
	}
	config.Webhook.Method = "post"
	if err := ValidateNotifyOptions(config); err != nil {
		t.Fatalf("case-insensitive method err=%v", err)
	}
	config.Webhook.Method = " POST"
	if err := ValidateNotifyOptions(config); !errors.Is(err, errInvalidNotifyOption) {
		t.Fatalf("padded method err=%v", err)
	}
	config.Email.Security = "ssl\n"
	if err := ValidateNotifyOptions(config); !errors.Is(err, errInvalidNotifyOption) {
		t.Fatalf("broken security err=%v", err)
	}
	config.Email.Security = "ssl"
	config.Webhook.Method = "PUT"
	if err := ValidateNotifyOptions(config); !errors.Is(err, errInvalidNotifyOption) {
		t.Fatalf("method err=%v", err)
	}
}

func TestSendEmailRejectsInvalidPort(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Email.Enabled = true
	config.Notifications.Email.Host = "smtp.example.test"
	config.Notifications.Email.Port = 70000
	config.Notifications.Email.Username = "monitor@example.test"
	config.Notifications.Email.To = "ops@example.test"
	err := New().Send(context.Background(), "email", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errInvalidNotifyPort) {
		t.Fatalf("smtp port err=%v", err)
	}
}

func TestSendTelegramRejectsOversizedProxyUser(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.Enabled = true
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	config.Notifications.Telegram.ChatID = "42"
	config.Notifications.Telegram.ProxyUser = strings.Repeat("u", maxNotifySecretRunes+1)
	err := New().Send(context.Background(), "telegram", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errInvalidNotifyIdentity) {
		t.Fatalf("proxy user err=%v", err)
	}
}

func TestSendTelegramRejectsInvalidSOCKSPort(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.Enabled = true
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	config.Notifications.Telegram.ChatID = "42"
	config.Notifications.Telegram.ProxyType = "socks5"
	config.Notifications.Telegram.ProxyIP = "127.0.0.1"
	config.Notifications.Telegram.ProxyPort = "not-a-port"
	err := New().Send(context.Background(), "telegram", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errInvalidNotifyPort) {
		t.Fatalf("socks port err=%v", err)
	}
}

func TestSendTelegramRejectsMetadataSOCKSProxy(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Telegram.Enabled = true
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	config.Notifications.Telegram.ChatID = "42"
	config.Notifications.Telegram.ProxyType = "socks5"
	config.Notifications.Telegram.ProxyIP = "100.100.100.200"
	config.Notifications.Telegram.ProxyPort = "1080"
	err := New().Send(context.Background(), "telegram", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("socks metadata err=%v", err)
	}
}

func TestSendTelegramSOCKSRejectsProxyRebindToMetadata(t *testing.T) {
	original := lookupNotifyIPs
	calls := 0
	lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		if host != "socks.example.test" {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		}
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		}
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	t.Cleanup(func() { lookupNotifyIPs = original })

	config := domain.Config{}
	config.Notifications.Telegram.Enabled = true
	config.Notifications.Telegram.Token = "123456:AA-secret-token-value"
	config.Notifications.Telegram.ChatID = "42"
	config.Notifications.Telegram.ProxyType = "socks5"
	config.Notifications.Telegram.ProxyIP = "socks.example.test"
	config.Notifications.Telegram.ProxyPort = "1080"
	err := New().Send(context.Background(), "telegram", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if err == nil || !strings.Contains(err.Error(), errForbiddenNotifyHost.Error()) {
		t.Fatalf("socks rebind err=%v", err)
	}
}

func TestValidateWebhookPayloadRejectsOversizedValues(t *testing.T) {
	if err := ValidateWebhookHeaders(strings.Repeat("h", maxWebhookHeadersRunes+1)); !errors.Is(err, errInvalidNotifyPayload) {
		t.Fatalf("headers err=%v", err)
	}
	if err := ValidateWebhookBody(strings.Repeat("b", maxWebhookBodyRunes+1)); !errors.Is(err, errInvalidNotifyPayload) {
		t.Fatalf("body err=%v", err)
	}
	if err := ValidateWebhookBody(strings.Repeat("b", maxWebhookBodyRunes)); err != nil {
		t.Fatalf("max body err=%v", err)
	}
}

func TestValidateWebhookHeadersRejectsHopByHopNames(t *testing.T) {
	if err := ValidateWebhookHeaders(`{"Authorization":"Bearer token-value"}`); err != nil {
		t.Fatalf("authorization header err=%v", err)
	}
	if err := ValidateWebhookHeaders("not-json"); !errors.Is(err, errInvalidNotifyPayload) {
		t.Fatalf("non-json headers err=%v", err)
	}
	if err := ValidateWebhookHeaders(`{"Host":"169.254.169.254"}`); !errors.Is(err, errInvalidNotifyHeader) {
		t.Fatalf("host header err=%v", err)
	}
	if err := ValidateWebhookHeaders(`{"Content-Length":"0"}`); !errors.Is(err, errInvalidNotifyHeader) {
		t.Fatalf("content-length header err=%v", err)
	}
	if err := ValidateWebhookHeaders(`{"":"x"}`); !errors.Is(err, errInvalidNotifyHeader) {
		t.Fatalf("empty header err=%v", err)
	}
	if err := ValidateWebhookHeaders(`{"` + strings.Repeat("N", maxWebhookHeaderNameRunes+1) + `":"v"}`); !errors.Is(err, errInvalidNotifyPayload) {
		t.Fatalf("oversized header name err=%v", err)
	}
	if err := ValidateWebhookHeaders(`{"X-Token":"` + strings.Repeat("v", maxWebhookHeaderValueRunes+1) + `"}`); !errors.Is(err, errInvalidNotifyPayload) {
		t.Fatalf("oversized header value err=%v", err)
	}
}

func TestValidateWebhookHeadersRejectsTooManyFields(t *testing.T) {
	fields := make([]string, 0, maxWebhookHeaderFields+1)
	for i := 0; i < maxWebhookHeaderFields+1; i++ {
		fields = append(fields, `"h`+strconv.Itoa(i)+`":"v"`)
	}
	raw := `{` + strings.Join(fields, ",") + `}`
	if err := ValidateWebhookHeaders(raw); !errors.Is(err, errInvalidNotifyPayload) {
		t.Fatalf("too many headers err=%v", err)
	}
}

func TestValidateSMTPIdentityRejectsOversizedMailbox(t *testing.T) {
	long := strings.Repeat("a", maxNotifyEmailRunes+1) + "@example.test"
	if err := ValidateSMTPIdentity(long, "ops@example.test"); !errors.Is(err, errInvalidNotifyIdentity) {
		t.Fatalf("username err=%v", err)
	}
	if err := ValidateSMTPIdentity("monitor@example.test", strings.Repeat("b", maxNotifyEmailRunes+1)); !errors.Is(err, errInvalidNotifyIdentity) {
		t.Fatalf("to err=%v", err)
	}
	if err := ValidateTelegramChatID(strings.Repeat("1", maxTelegramChatRunes+1)); !errors.Is(err, errInvalidNotifyIdentity) {
		t.Fatalf("chat id err=%v", err)
	}
	if err := ValidateTelegramChatID("-100123"); err != nil {
		t.Fatalf("normal chat id err=%v", err)
	}
}

func TestValidateNotifySecretRejectsOversizedCredentials(t *testing.T) {
	if err := ValidateNotifySecret(strings.Repeat("p", maxNotifySecretRunes+1)); !errors.Is(err, errInvalidNotifyIdentity) {
		t.Fatalf("secret err=%v", err)
	}
	if err := ValidateNotifySecret(strings.Repeat("p", maxNotifySecretRunes)); err != nil {
		t.Fatalf("max secret err=%v", err)
	}
	if err := ValidateNotifySecret("proxy-user\nvalue"); !errors.Is(err, errInvalidNotifyHeader) {
		t.Fatalf("break err=%v", err)
	}
	if err := ValidateNotifySecret(domain.ClearSecretSentinel); err != nil {
		t.Fatalf("clear sentinel err=%v", err)
	}
	config := domain.NotificationConfig{}
	config.Telegram.ProxyUser = strings.Repeat("u", maxNotifySecretRunes+1)
	if err := ValidateNotifyCredentials(config); !errors.Is(err, errInvalidNotifyIdentity) {
		t.Fatalf("proxy user err=%v", err)
	}
}

func TestSendEmailRejectsHeaderInjection(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Email.Enabled = true
	config.Notifications.Email.Host = "smtp.example.test"
	config.Notifications.Email.Port = 587
	config.Notifications.Email.Username = "monitor@example.test"
	config.Notifications.Email.To = "ops@example.test\r\nBcc: attacker@evil.test"
	err := New().Send(context.Background(), "email", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errInvalidNotifyHeader) {
		t.Fatalf("to injection err=%v", err)
	}
	config.Notifications.Email.To = "ops@example.test"
	config.Notifications.Email.Username = "monitor@example.test\nFrom: forged@evil.test"
	err = New().Send(context.Background(), "email", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errInvalidNotifyHeader) {
		t.Fatalf("from injection err=%v", err)
	}
}

func TestSendWebhookRejectsHeaderInjection(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Webhook.Enabled = true
	config.Notifications.Webhook.URL = "http://127.0.0.1:1/hooks/test"
	config.Notifications.Webhook.Method = "POST"
	config.Notifications.Webhook.Type = "JSON"
	config.Notifications.Webhook.Headers = "{\"X-Auth\":\"leak\\r\\nX-Injected: 1\"}"
	err := New().Send(context.Background(), "webhook", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errInvalidNotifyHeader) {
		t.Fatalf("webhook header injection err=%v", err)
	}
}

func TestSendEmailRejectsMetadataHost(t *testing.T) {
	config := domain.Config{}
	config.Notifications.Email.Enabled = true
	config.Notifications.Email.Host = "100.100.100.200"
	config.Notifications.Email.Port = 465
	config.Notifications.Email.Username = "monitor@example.test"
	config.Notifications.Email.To = "ops@example.test"
	err := New().Send(context.Background(), "email", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("send err=%v", err)
	}
}

func TestSendEmailRejectsHostnameResolvedToMetadata(t *testing.T) {
	original := lookupNotifyIPs
	lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "smtp.metadata.example.test" {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return []net.IP{net.ParseIP("1.2.3.4")}, nil
	}
	t.Cleanup(func() { lookupNotifyIPs = original })

	config := domain.Config{}
	config.Notifications.Email.Enabled = true
	config.Notifications.Email.Host = "smtp.metadata.example.test"
	config.Notifications.Email.Port = 465
	config.Notifications.Email.Username = "monitor@example.test"
	config.Notifications.Email.To = "ops@example.test"
	err := New().Send(context.Background(), "email", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("send err=%v", err)
	}
}

func TestNotifyDialContextRejectsMetadataIP(t *testing.T) {
	_, err := notifyDialContext(context.Background(), "tcp", net.JoinHostPort("169.254.169.254", "80"))
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("link-local dial err=%v", err)
	}
	_, err = notifyDialContext(context.Background(), "tcp", net.JoinHostPort("100.100.100.200", "80"))
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("aliyun metadata dial err=%v", err)
	}
}

func TestNotifyDialContextRejectsTooManyResolvedIPs(t *testing.T) {
	original := lookupNotifyIPs
	lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		ips := make([]net.IP, maxNotifyResolvedIPs+1)
		for i := range ips {
			ips[i] = net.IPv4(8, 8, 8, byte(i+1))
		}
		return ips, nil
	}
	t.Cleanup(func() { lookupNotifyIPs = original })
	_, err := notifyDialContext(context.Background(), "tcp", net.JoinHostPort("hooks.example.test", "443"))
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("too many answers err=%v", err)
	}
}

func TestNotifyDialContextRejectsNonTCP(t *testing.T) {
	_, err := notifyDialContext(context.Background(), "udp", net.JoinHostPort("hooks.example.test", "443"))
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("udp dial err=%v", err)
	}
}

func TestSOCKSTransportDialContextRejectsMetadataDestination(t *testing.T) {
	dial := socksTransportDialContext(notifyContextDialer{})
	_, err := dial(context.Background(), "tcp", net.JoinHostPort("169.254.169.254", "443"))
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("ip dest err=%v", err)
	}
	_, err = dial(context.Background(), "tcp", net.JoinHostPort("metadata.google.internal", "443"))
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("hostname dest err=%v", err)
	}
	_, err = dial(context.Background(), "udp", net.JoinHostPort("proxy.example.test", "443"))
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("udp dest err=%v", err)
	}
}

func TestSendWebhookRejectsDNSRebindingToMetadata(t *testing.T) {
	original := lookupNotifyIPs
	calls := 0
	lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		if host != "rebind.example.test" {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		}
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		}
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	t.Cleanup(func() { lookupNotifyIPs = original })

	config := domain.Config{}
	config.Notifications.Webhook.Enabled = true
	config.Notifications.Webhook.URL = "http://rebind.example.test/hooks/test"
	config.Notifications.Webhook.Method = "POST"
	config.Notifications.Webhook.Type = "JSON"
	err := New().Send(context.Background(), "webhook", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if err == nil || !strings.Contains(err.Error(), errForbiddenNotifyHost.Error()) {
		t.Fatalf("send err=%v", err)
	}
	if calls < 2 {
		t.Fatalf("dial-time lookup skipped, calls=%d", calls)
	}
}

func TestSendEmailRejectsDNSRebindingToMetadata(t *testing.T) {
	original := lookupNotifyIPs
	calls := 0
	lookupNotifyIPs = func(ctx context.Context, host string) ([]net.IP, error) {
		if host != "smtp.rebind.example.test" {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		}
		calls++
		if calls == 1 {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		}
		return []net.IP{net.ParseIP("100.100.100.200")}, nil
	}
	t.Cleanup(func() { lookupNotifyIPs = original })

	config := domain.Config{}
	config.Notifications.Email.Enabled = true
	config.Notifications.Email.Host = "smtp.rebind.example.test"
	config.Notifications.Email.Port = 587
	config.Notifications.Email.Security = "starttls"
	config.Notifications.Email.Username = "monitor@example.test"
	config.Notifications.Email.To = "ops@example.test"
	err := New().Send(context.Background(), "email", domain.NotificationEvent{Title: "t", Summary: "s"}, config)
	if !errors.Is(err, errForbiddenNotifyHost) {
		t.Fatalf("send err=%v", err)
	}
	if calls < 2 {
		t.Fatalf("dial-time lookup skipped, calls=%d", calls)
	}
}

func TestNotifyHTTPClientRequiresTLS12(t *testing.T) {
	transport, ok := New().httpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("default notify transport TLS = %#v", New().httpClient.Transport)
	}
	secured := tls12Transport(&http.Transport{})
	if secured.TLSClientConfig == nil || secured.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("tls12Transport = %#v", secured.TLSClientConfig)
	}
	if transport.DialContext == nil {
		t.Fatal("notify HTTP dialer must pin destinations at connect time")
	}
}

func TestReadDotResponseBoundsSize(t *testing.T) {
	got, err := readDotResponse(bufio.NewReader(strings.NewReader("250 ok\r\n.\r\n")))
	if err != nil || string(got) != "250 ok\r\n" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	huge := strings.Repeat("x", maxSMTPDotResponseBytes+1) + "\r\n.\r\n"
	_, err = readDotResponse(bufio.NewReader(strings.NewReader(huge)))
	if err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("oversized err=%v", err)
	}
}

func TestClipNotifyErrorText(t *testing.T) {
	if got := clipNotifyErrorText("  boom  "); got != "boom" {
		t.Fatalf("trim=%q", got)
	}
	long := strings.Repeat("m", maxNotifyErrorRunes+40)
	got := clipNotifyErrorText(long)
	if !strings.HasSuffix(got, "...") {
		t.Fatalf("missing clip marker: %q", got)
	}
	if runes := []rune(got); len(runes) != maxNotifyErrorRunes+3 {
		t.Fatalf("clipped len=%d", len(runes))
	}
}
