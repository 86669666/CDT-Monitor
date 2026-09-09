package httpapi

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/engine"
	"github.com/wang4386/CDT-Monitor/internal/notify"
	"github.com/wang4386/CDT-Monitor/internal/security"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

const testAdminPassword = "Strong-Password-42!"

func initializedAuthStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	config := domain.Config{
		AdminPassword:    testAdminPassword,
		TrafficThreshold: 95,
		ShutdownMode:     "KeepCharging",
		ThresholdAction:  "stop_and_notify",
		APIInterval:      600,
		Timezone:         "Asia/Shanghai",
		Accounts: []domain.Account{{
			AccessKeyID:     "LTAItest",
			AccessKeySecret: "super-secret-ak",
			RegionID:        "cn-hongkong",
			InstanceID:      "i-test",
			MaxTraffic:      200,
			SiteType:        "china",
		}},
		Notifications: domain.NotificationConfig{
			Email:    domain.EmailConfig{Password: "smtp-password-value"},
			Telegram: domain.TelegramConfig{Token: "telegram-token-value"},
			Webhook:  domain.WebhookConfig{Secret: "webhook-secret-value", Headers: "X-Auth: leak-me"},
		},
	}
	if err = st.Setup(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	return st
}

func testAPIHandler(t *testing.T, st *store.Store) http.Handler {
	t.Helper()
	eng := engine.New(st, nil, notify.New(), slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	server := New(st, eng, fstest.MapFS{"index.html": {Data: []byte("ok")}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return server.Handler()
}

func doRequest(t *testing.T, handler http.Handler, method, path, body string, cookies []*http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, "https://monitor.example.com"+path, reader)
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("X-Forwarded-Proto", "https")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for _, cookie := range cookies {
		request.AddCookie(cookie)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func loginCookies(t *testing.T, handler http.Handler) (session, csrf *http.Cookie) {
	t.Helper()
	response := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"`+testAdminPassword+`"}`, nil, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", response.Code, response.Body.String())
	}
	cookies := response.Result().Cookies()
	session = cookieNamed(cookies, "cdt_session")
	csrf = cookieNamed(cookies, "cdt_csrf")
	if session == nil || csrf == nil || session.Value == "" || csrf.Value == "" {
		t.Fatalf("missing auth cookies: %#v", cookies)
	}
	if !session.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if csrf.HttpOnly {
		t.Fatal("CSRF cookie must be readable by the frontend")
	}
	if !session.Secure || !csrf.Secure {
		t.Fatal("auth cookies must be Secure on HTTPS")
	}
	if session.SameSite != http.SameSiteStrictMode || csrf.SameSite != http.SameSiteStrictMode {
		t.Fatalf("auth cookies must be SameSite=Strict: session=%v csrf=%v", session.SameSite, csrf.SameSite)
	}
	var payload struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.CSRFToken != csrf.Value {
		t.Fatalf("csrf_token %q does not match cookie %q", payload.CSRFToken, csrf.Value)
	}
	if csrf.Value != csrfToken(session.Value) {
		t.Fatalf("csrf cookie %q is not bound to session", csrf.Value)
	}
	return session, csrf
}

func TestLoginCookiesAndConfigRedaction(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)

	response := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{session, csrf}, nil)
	if response.Code != http.StatusOK {
		t.Fatalf("config status = %d, body = %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, secret := range []string{testAdminPassword, "super-secret-ak", "smtp-password-value", "telegram-token-value", "webhook-secret-value", "leak-me"} {
		if strings.Contains(body, secret) {
			t.Fatalf("config response leaked %q: %s", secret, body)
		}
	}
	var config domain.Config
	if err := json.Unmarshal(response.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if !config.Accounts[0].SecretConfigured || config.Accounts[0].AccessKeySecret != "" {
		t.Fatalf("account secret flags = %#v", config.Accounts[0])
	}
	if !config.Notifications.Email.PasswordConfigured || config.Notifications.Email.Password != "" {
		t.Fatalf("email secret flags = %#v", config.Notifications.Email)
	}
	if !config.Notifications.Telegram.TokenConfigured || config.Notifications.Telegram.Token != "" {
		t.Fatalf("telegram secret flags = %#v", config.Notifications.Telegram)
	}
	if !config.Notifications.Webhook.SecretConfigured || !config.Notifications.Webhook.HeadersConfigured || config.Notifications.Webhook.Secret != "" || config.Notifications.Webhook.Headers != "" {
		t.Fatalf("webhook secret flags = %#v", config.Notifications.Webhook)
	}
}

func TestWebhookHeadersStayUntilClearedOverHTTP(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}

	got := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", cookies, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get config status = %d body = %s", got.Code, got.Body.String())
	}
	var config domain.Config
	if err := json.Unmarshal(got.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	if !config.Notifications.Webhook.HeadersConfigured || !config.Notifications.Webhook.SecretConfigured {
		t.Fatalf("expected headers and secret to be configured: %#v", config.Notifications.Webhook)
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	kept := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), cookies, headers)
	if kept.Code != http.StatusOK {
		t.Fatalf("scrubbed save status = %d body = %s", kept.Code, kept.Body.String())
	}
	loaded, err := st.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Notifications.Webhook.Headers != "X-Auth: leak-me" || loaded.Notifications.Webhook.Secret != "webhook-secret-value" {
		t.Fatalf("empty scrubbed PUT must keep webhook secrets: %#v", loaded.Notifications.Webhook)
	}

	config.Notifications.Webhook.Headers = domain.ClearSecretSentinel
	config.Notifications.Webhook.Secret = domain.ClearSecretSentinel
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	cleared := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), cookies, headers)
	if cleared.Code != http.StatusOK {
		t.Fatalf("clear save status = %d body = %s", cleared.Code, cleared.Body.String())
	}
	reload := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", cookies, nil)
	if reload.Code != http.StatusOK {
		t.Fatalf("reload status = %d body = %s", reload.Code, reload.Body.String())
	}
	var clearedConfig domain.Config
	if err = json.Unmarshal(reload.Body.Bytes(), &clearedConfig); err != nil {
		t.Fatal(err)
	}
	if clearedConfig.Notifications.Webhook.HeadersConfigured || clearedConfig.Notifications.Webhook.SecretConfigured || clearedConfig.Notifications.Webhook.Headers != "" || clearedConfig.Notifications.Webhook.Secret != "" {
		t.Fatalf("cleared webhook flags = %#v", clearedConfig.Notifications.Webhook)
	}
	if strings.Contains(reload.Body.String(), "leak-me") || strings.Contains(reload.Body.String(), "webhook-secret-value") || strings.Contains(reload.Body.String(), domain.ClearSecretSentinel) {
		t.Fatalf("cleared config leaked secret material: %s", reload.Body.String())
	}
	loaded, err = st.GetConfig(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Notifications.Webhook.Headers != "" || loaded.Notifications.Webhook.Secret != "" {
		t.Fatalf("store still has webhook secrets: %#v", loaded.Notifications.Webhook)
	}
}

func TestWebhookURLIsReturnedButNotStoredPlain(t *testing.T) {
	st := initializedAuthStore(t)
	ctx := t.Context()
	config, err := st.GetConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "https://example.test/hook?access_token=url-token-value"
	config.AdminPassword = ""
	config.Accounts[0].AccessKeySecret = ""
	config.Notifications.Webhook.URL = endpoint
	if err = st.SaveConfig(ctx, config); err != nil {
		t.Fatal(err)
	}
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	got := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{session, csrf}, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get config status = %d body = %s", got.Code, got.Body.String())
	}
	body := got.Body.String()
	if !strings.Contains(body, endpoint) {
		t.Fatalf("admin GET must return webhook URL for editing: %s", body)
	}
	if strings.Contains(body, "enc:v1:") {
		t.Fatalf("GET config leaked ciphertext: %s", body)
	}
	var stored string
	if err = st.DB().QueryRow(`SELECT value FROM settings WHERE key='notify_wh_url'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !security.IsEncrypted(stored) || strings.Contains(stored, "url-token-value") {
		t.Fatalf("webhook URL must stay encrypted at rest: %q", stored)
	}
}

func TestAdminMutationRequiresMatchingCSRF(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)

	missing := doRequest(t, handler, http.MethodDelete, "/api/v1/logs", "", []*http.Cookie{session, csrf}, nil)
	if missing.Code != http.StatusForbidden || !strings.Contains(missing.Body.String(), "csrf_failed") {
		t.Fatalf("missing CSRF status = %d body = %s", missing.Code, missing.Body.String())
	}

	wrong := doRequest(t, handler, http.MethodDelete, "/api/v1/logs", "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": "not-the-token"})
	if wrong.Code != http.StatusForbidden || !strings.Contains(wrong.Body.String(), "csrf_failed") {
		t.Fatalf("wrong CSRF status = %d body = %s", wrong.Code, wrong.Body.String())
	}

	ok := doRequest(t, handler, http.MethodDelete, "/api/v1/logs", "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if ok.Code != http.StatusOK {
		t.Fatalf("valid CSRF status = %d body = %s", ok.Code, ok.Body.String())
	}
}

func TestCSRFTokenIsBoundToSession(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	_, firstCSRF := loginCookies(t, handler)
	secondSession, secondCSRF := loginCookies(t, handler)

	if firstCSRF.Value == secondCSRF.Value {
		t.Fatal("exclusive login must issue a new CSRF token")
	}

	reused := doRequest(t, handler, http.MethodDelete, "/api/v1/logs", "", []*http.Cookie{secondSession, firstCSRF}, map[string]string{"X-CDT-CSRF": firstCSRF.Value})
	if reused.Code != http.StatusForbidden || !strings.Contains(reused.Body.String(), "csrf_failed") {
		t.Fatalf("previous CSRF with new session status = %d body = %s", reused.Code, reused.Body.String())
	}

	tossed := &http.Cookie{Name: "cdt_csrf", Value: "tossed-csrf-token"}
	cookieToss := doRequest(t, handler, http.MethodDelete, "/api/v1/logs", "", []*http.Cookie{secondSession, tossed}, map[string]string{"X-CDT-CSRF": tossed.Value})
	if cookieToss.Code != http.StatusForbidden || !strings.Contains(cookieToss.Body.String(), "csrf_failed") {
		t.Fatalf("tossed CSRF status = %d body = %s", cookieToss.Code, cookieToss.Body.String())
	}

	ok := doRequest(t, handler, http.MethodDelete, "/api/v1/logs", "", []*http.Cookie{secondSession, secondCSRF}, map[string]string{"X-CDT-CSRF": secondCSRF.Value})
	if ok.Code != http.StatusOK {
		t.Fatalf("session-bound CSRF status = %d body = %s", ok.Code, ok.Body.String())
	}
}

func TestAPIKeyScopesAndTokenAreNotRelisted(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)

	created := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"widget","scopes":["widget:read"]}`, []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if created.Code != http.StatusCreated {
		t.Fatalf("create API key status = %d body = %s", created.Code, created.Body.String())
	}
	var createdPayload struct {
		Token string `json:"token"`
		Key   struct {
			ID     int64    `json:"id"`
			Name   string   `json:"name"`
			Scopes []string `json:"scopes"`
		} `json:"key"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdPayload); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(createdPayload.Token, "cdt_") || createdPayload.Key.ID == 0 {
		t.Fatalf("create payload = %#v", createdPayload)
	}

	listed := doRequest(t, handler, http.MethodGet, "/api/v1/api-keys", "", []*http.Cookie{session, csrf}, nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("list API keys status = %d body = %s", listed.Code, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), createdPayload.Token) {
		t.Fatalf("API key list leaked token: %s", listed.Body.String())
	}

	status := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, map[string]string{"X-API-Key": createdPayload.Token})
	if status.Code != http.StatusOK {
		t.Fatalf("widget status status = %d body = %s", status.Code, status.Body.String())
	}

	forbidden := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/refresh", `{}`, nil, map[string]string{"X-API-Key": createdPayload.Token})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget refresh status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}

	unauthorized := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous config status = %d body = %s", unauthorized.Code, unauthorized.Body.String())
	}
}

func TestAPIKeyLastUsedIsListedWithoutToken(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	created := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"widget","scopes":["widget:read"]}`, []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if created.Code != http.StatusCreated {
		t.Fatalf("create API key status = %d body = %s", created.Code, created.Body.String())
	}
	var createdPayload struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createdPayload); err != nil {
		t.Fatal(err)
	}
	unused := doRequest(t, handler, http.MethodGet, "/api/v1/api-keys", "", []*http.Cookie{session, csrf}, nil)
	if unused.Code != http.StatusOK || strings.Contains(unused.Body.String(), `"last_used_at"`) {
		t.Fatalf("unused key list status = %d body = %s", unused.Code, unused.Body.String())
	}
	status := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, map[string]string{"X-API-Key": createdPayload.Token})
	if status.Code != http.StatusOK {
		t.Fatalf("widget status = %d body = %s", status.Code, status.Body.String())
	}
	used := doRequest(t, handler, http.MethodGet, "/api/v1/api-keys", "", []*http.Cookie{session, csrf}, nil)
	if used.Code != http.StatusOK || !strings.Contains(used.Body.String(), `"last_used_at"`) {
		t.Fatalf("used key list status = %d body = %s", used.Code, used.Body.String())
	}
	if strings.Contains(used.Body.String(), createdPayload.Token) {
		t.Fatalf("API key list leaked token after use: %s", used.Body.String())
	}
}

func TestJSONAPIsRejectQueryStringAPIKey(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	query := doRequest(t, handler, http.MethodGet, "/api/v1/status?key="+widgetToken, "", nil, nil)
	if query.Code != http.StatusUnauthorized {
		t.Fatalf("query status key status = %d body = %s", query.Code, query.Body.String())
	}
	header := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, map[string]string{"X-API-Key": widgetToken})
	if header.Code != http.StatusOK {
		t.Fatalf("header status key status = %d body = %s", header.Code, header.Body.String())
	}
	_, cronToken, err := st.CreateAPIKey(t.Context(), "cron", []string{"cron:run"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy := doRequest(t, handler, http.MethodGet, "/monitor.php?key="+cronToken, "", nil, nil)
	if legacy.Code != http.StatusAccepted {
		t.Fatalf("legacy query key status = %d body = %s", legacy.Code, legacy.Body.String())
	}
}

func TestLoginInvalidatesPreviousSession(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	firstSession, firstCSRF := loginCookies(t, handler)
	secondSession, secondCSRF := loginCookies(t, handler)
	denied := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{firstSession, firstCSRF}, nil)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("old session status = %d body = %s", denied.Code, denied.Body.String())
	}
	ok := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{secondSession, secondCSRF}, nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("new session status = %d body = %s", ok.Code, ok.Body.String())
	}
}

func TestLogoutInvalidatesSession(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	logout := doRequest(t, handler, http.MethodPost, "/api/v1/auth/logout", "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if logout.Code != http.StatusOK {
		t.Fatalf("logout status = %d body = %s", logout.Code, logout.Body.String())
	}
	denied := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{session, csrf}, nil)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out config status = %d body = %s", denied.Code, denied.Body.String())
	}
}

func TestLoginLockoutAfterRepeatedFailures(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	for i := 0; i < 5; i++ {
		response := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong-password-xx"}`, nil, nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body = %s", i+1, response.Code, response.Body.String())
		}
		if cookieNamed(response.Result().Cookies(), "cdt_session") != nil {
			t.Fatal("failed login must not set a session cookie")
		}
	}
	locked := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"`+testAdminPassword+`"}`, nil, nil)
	if locked.Code != http.StatusTooManyRequests || !strings.Contains(locked.Body.String(), "login_locked") {
		t.Fatalf("lockout status = %d body = %s", locked.Code, locked.Body.String())
	}
}

func TestLegacyMonitorRequiresCronScope(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	ctx := t.Context()
	_, cronToken, err := st.CreateAPIKey(ctx, "cron", []string{"cron:run"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, widgetToken, err := st.CreateAPIKey(ctx, "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	headerOK := doRequest(t, handler, http.MethodGet, "/monitor.php", "", nil, map[string]string{"X-API-Key": cronToken})
	if headerOK.Code != http.StatusAccepted {
		t.Fatalf("header cron status = %d body = %s", headerOK.Code, headerOK.Body.String())
	}
	queryOK := doRequest(t, handler, http.MethodGet, "/monitor.php?key="+cronToken, "", nil, nil)
	if queryOK.Code != http.StatusAccepted {
		t.Fatalf("query cron status = %d body = %s", queryOK.Code, queryOK.Body.String())
	}
	forbidden := doRequest(t, handler, http.MethodGet, "/monitor.php", "", nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusUnauthorized {
		t.Fatalf("widget cron status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
	missing := doRequest(t, handler, http.MethodGet, "/monitor.php", "", nil, nil)
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing cron status = %d body = %s", missing.Code, missing.Body.String())
	}
}

func loginAttempt(t *testing.T, handler http.Handler, password, remoteAddr, forwardedFor string) *httptest.ResponseRecorder {
	t.Helper()
	headers := map[string]string{}
	if forwardedFor != "" {
		headers["X-Forwarded-For"] = forwardedFor
	}
	request := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/auth/login", strings.NewReader(`{"password":"`+password+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.RemoteAddr = remoteAddr
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestLoginLockoutIgnoresSpoofedForwardedFor(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	for i := 0; i < 5; i++ {
		response := loginAttempt(t, handler, "wrong-password-xx", "203.0.113.10:443", "198.51.100.1")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body = %s", i+1, response.Code, response.Body.String())
		}
	}
	locked := loginAttempt(t, handler, testAdminPassword, "203.0.113.10:443", "198.51.100.9")
	if locked.Code != http.StatusTooManyRequests || !strings.Contains(locked.Body.String(), "login_locked") {
		t.Fatalf("spoofed X-Forwarded-For must not bypass lockout, status = %d body = %s", locked.Code, locked.Body.String())
	}
}

func TestLoginLockoutTrustsForwardedForFromLoopback(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	for i := 0; i < 5; i++ {
		response := loginAttempt(t, handler, "wrong-password-xx", "127.0.0.1:8080", "198.51.100.20")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body = %s", i+1, response.Code, response.Body.String())
		}
	}
	ok := loginAttempt(t, handler, testAdminPassword, "127.0.0.1:8080", "198.51.100.21")
	if ok.Code != http.StatusOK {
		t.Fatalf("loopback proxy should isolate client IPs, status = %d body = %s", ok.Code, ok.Body.String())
	}
}

func TestCreateAPIKeyRejectsPastExpiryHTTP(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	created := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"old","scopes":["widget:read"],"expires_at":"`+past+`"}`, []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if created.Code != http.StatusBadRequest || !strings.Contains(created.Body.String(), "api_key_failed") {
		t.Fatalf("past expiry status = %d body = %s", created.Code, created.Body.String())
	}
	if strings.Contains(created.Body.String(), "expiry must be in the future") {
		t.Fatalf("past expiry leaked store error: %s", created.Body.String())
	}
}

func TestCreateAPIKeyRejectsEmptyNameAndScopes(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	for _, body := range []string{`{"name":"","scopes":["widget:read"]}`, `{"name":"   ","scopes":["widget:read"]}`, `{"name":"widget","scopes":[]}`} {
		got := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", body, cookies, headers)
		if got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "api_key_failed") {
			t.Fatalf("body %s status = %d response = %s", body, got.Code, got.Body.String())
		}
		if strings.Contains(got.Body.String(), "name and at least one scope") {
			t.Fatalf("empty key leaked store error: %s", got.Body.String())
		}
	}
	listed := doRequest(t, handler, http.MethodGet, "/api/v1/api-keys", "", cookies, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"keys":[]`) {
		t.Fatalf("empty key list status = %d body = %s", listed.Code, listed.Body.String())
	}
}

func TestLegacyAdminAPIKeyCannotAccessAdminOrWidget(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	token := "cdt_legacy_admin_http"
	if _, err := st.DB().Exec(`INSERT INTO api_keys(name,token_hash,scopes,created_at) VALUES('admin',?,'["admin"]',unixepoch())`, security.TokenHash(token)); err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"X-API-Key": token}
	config := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", nil, headers)
	if config.Code != http.StatusUnauthorized {
		t.Fatalf("legacy admin config status = %d body = %s", config.Code, config.Body.String())
	}
	status := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, headers)
	if status.Code != http.StatusUnauthorized {
		t.Fatalf("legacy admin status status = %d body = %s", status.Code, status.Body.String())
	}
}

func TestCreateAPIKeyRejectsUnknownScopesHTTP(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	admin := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"root","scopes":["admin"]}`, cookies, headers)
	if admin.Code != http.StatusBadRequest || !strings.Contains(admin.Body.String(), "invalid_scope") {
		t.Fatalf("admin scope status = %d body = %s", admin.Code, admin.Body.String())
	}
	mixed := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"mixed","scopes":["widget:read","admin"]}`, cookies, headers)
	if mixed.Code != http.StatusBadRequest || !strings.Contains(mixed.Body.String(), "invalid_scope") {
		t.Fatalf("mixed scope status = %d body = %s", mixed.Code, mixed.Body.String())
	}
	listed := doRequest(t, handler, http.MethodGet, "/api/v1/api-keys", "", cookies, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"keys":[]`) {
		t.Fatalf("unknown scope list status = %d body = %s", listed.Code, listed.Body.String())
	}
}

func TestCreateAPIKeyDeduplicatesScopesHTTP(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	created := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"widget","scopes":["widget:read","widget:read","instance:control"]}`, []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", created.Code, created.Body.String())
	}
	var payload struct {
		Key struct {
			Scopes []string `json:"scopes"`
		} `json:"key"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Key.Scopes) != 2 || payload.Key.Scopes[0] != "widget:read" || payload.Key.Scopes[1] != "instance:control" {
		t.Fatalf("scopes=%v", payload.Key.Scopes)
	}
}

func TestLegacyMonitorAcceptsBearerToken(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	_, token, err := st.CreateAPIKey(t.Context(), "cron", []string{"cron:run"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ok := doRequest(t, handler, http.MethodGet, "/monitor.php", "", nil, map[string]string{"Authorization": "Bearer " + token})
	if ok.Code != http.StatusAccepted {
		t.Fatalf("bearer cron status = %d body = %s", ok.Code, ok.Body.String())
	}
}

func TestExpiredAPIKeyCannotReadStatus(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	token := "cdt_expired_http_token"
	_, err := st.DB().Exec(`INSERT INTO api_keys(name,token_hash,scopes,created_at,expires_at) VALUES('expired',?,'["widget:read"]',unixepoch(),unixepoch()-30)`, security.TokenHash(token))
	if err != nil {
		t.Fatal(err)
	}
	denied := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, map[string]string{"X-API-Key": token})
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("expired key status = %d body = %s", denied.Code, denied.Body.String())
	}
}

func TestAPIKeyControlSkipsCSRFAndWidgetCanReadHistory(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	ctx := t.Context()
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	id := accounts[0].ID
	_, controlToken, err := st.CreateAPIKey(ctx, "control", []string{"instance:control"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, widgetToken, err := st.CreateAPIKey(ctx, "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	refresh := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+itoa(id)+"/refresh", `{}`, nil, map[string]string{"X-API-Key": controlToken})
	if refresh.Code != http.StatusAccepted {
		t.Fatalf("control refresh without CSRF status = %d body = %s", refresh.Code, refresh.Body.String())
	}
	start := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+itoa(id)+"/actions/start", `{}`, nil, map[string]string{"X-API-Key": controlToken})
	if start.Code != http.StatusAccepted {
		t.Fatalf("control start without CSRF status = %d body = %s", start.Code, start.Body.String())
	}
	config := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", nil, map[string]string{"X-API-Key": controlToken})
	if config.Code != http.StatusForbidden {
		t.Fatalf("control key must not read config, status = %d body = %s", config.Code, config.Body.String())
	}

	history := doRequest(t, handler, http.MethodGet, "/api/v1/accounts/"+itoa(id)+"/history", "", nil, map[string]string{"X-API-Key": widgetToken})
	if history.Code != http.StatusOK || !strings.Contains(history.Body.String(), `"hourly"`) {
		t.Fatalf("widget history status = %d body = %s", history.Code, history.Body.String())
	}
	forbidden := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+itoa(id)+"/actions/stop", `{}`, nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget stop status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
}

func itoa(id int64) string {
	return strconv.FormatInt(id, 10)
}

func TestRefreshJobDedupAndWidgetJobRead(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	ctx := t.Context()
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	id := itoa(accounts[0].ID)
	_, controlToken, err := st.CreateAPIKey(ctx, "control", []string{"instance:control"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, widgetToken, err := st.CreateAPIKey(ctx, "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+id+"/refresh", `{}`, nil, map[string]string{"X-API-Key": controlToken})
	second := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+id+"/refresh", `{}`, nil, map[string]string{"X-API-Key": controlToken})
	if first.Code != http.StatusAccepted || second.Code != http.StatusAccepted {
		t.Fatalf("refresh status first=%d second=%d body=%s %s", first.Code, second.Code, first.Body.String(), second.Body.String())
	}
	var firstJob, secondJob domain.Job
	if err = json.Unmarshal(first.Body.Bytes(), &firstJob); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(second.Body.Bytes(), &secondJob); err != nil {
		t.Fatal(err)
	}
	if firstJob.ID == "" || firstJob.ID != secondJob.ID {
		t.Fatalf("expected same refresh job, first=%#v second=%#v", firstJob, secondJob)
	}
	job := doRequest(t, handler, http.MethodGet, "/api/v1/jobs/"+firstJob.ID, "", nil, map[string]string{"X-API-Key": widgetToken})
	if job.Code != http.StatusOK || !strings.Contains(job.Body.String(), firstJob.ID) {
		t.Fatalf("widget job status = %d body = %s", job.Code, job.Body.String())
	}
	controlJob := doRequest(t, handler, http.MethodGet, "/api/v1/jobs/"+firstJob.ID, "", nil, map[string]string{"X-API-Key": controlToken})
	if controlJob.Code != http.StatusOK || !strings.Contains(controlJob.Body.String(), firstJob.ID) {
		t.Fatalf("control key should read its job, status = %d body = %s", controlJob.Code, controlJob.Body.String())
	}
	anonymous := doRequest(t, handler, http.MethodGet, "/api/v1/jobs/"+firstJob.ID, "", nil, nil)
	if anonymous.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous job status = %d body = %s", anonymous.Code, anonymous.Body.String())
	}
}

func TestCronKeyCannotAccessAdminOrWidgetAPIs(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	_, cronToken, err := st.CreateAPIKey(t.Context(), "cron", []string{"cron:run"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"X-API-Key": cronToken}
	status := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, headers)
	if status.Code != http.StatusForbidden {
		t.Fatalf("cron status = %d body = %s", status.Code, status.Body.String())
	}
	refresh := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/refresh", `{}`, nil, headers)
	if refresh.Code != http.StatusForbidden {
		t.Fatalf("cron refresh = %d body = %s", refresh.Code, refresh.Body.String())
	}
	config := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", nil, headers)
	if config.Code != http.StatusForbidden {
		t.Fatalf("cron config = %d body = %s", config.Code, config.Body.String())
	}
	monitor := doRequest(t, handler, http.MethodGet, "/monitor.php", "", nil, headers)
	if monitor.Code != http.StatusAccepted {
		t.Fatalf("cron monitor = %d body = %s", monitor.Code, monitor.Body.String())
	}
}

func TestRevokedAPIKeyCannotReadStatus(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	created := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"widget","scopes":["widget:read"]}`, []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d body = %s", created.Code, created.Body.String())
	}
	var payload struct {
		Token string `json:"token"`
		Key   struct {
			ID int64 `json:"id"`
		} `json:"key"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	revoked := doRequest(t, handler, http.MethodDelete, "/api/v1/api-keys/"+itoa(payload.Key.ID), "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke status = %d body = %s", revoked.Code, revoked.Body.String())
	}
	denied := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, map[string]string{"X-API-Key": payload.Token})
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key status = %d body = %s", denied.Code, denied.Body.String())
	}
}

func TestSetupRateLimitAndRejectsReinit(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	handler := testAPIHandler(t, st)
	for i := 0; i < 5; i++ {
		response := doRequest(t, handler, http.MethodPost, "/api/v1/setup", `{"not":"valid"}`, nil, nil)
		if response.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d was rate limited too early: %s", i+1, response.Body.String())
		}
	}
	limited := doRequest(t, handler, http.MethodPost, "/api/v1/setup", `{"not":"valid"}`, nil, nil)
	if limited.Code != http.StatusTooManyRequests || !strings.Contains(limited.Body.String(), "rate_limited") {
		t.Fatalf("setup rate limit status = %d body = %s", limited.Code, limited.Body.String())
	}

	st2 := initializedAuthStore(t)
	handler2 := testAPIHandler(t, st2)
	again := doRequest(t, handler2, http.MethodPost, "/api/v1/setup", `{"admin_password":"Another-Password-99!","traffic_threshold":95,"shutdown_mode":"KeepCharging","threshold_action":"stop_and_notify","api_interval":600,"timezone":"Asia/Shanghai"}`, nil, nil)
	if again.Code != http.StatusBadRequest || !strings.Contains(again.Body.String(), "setup_failed") {
		t.Fatalf("re-init status = %d body = %s", again.Code, again.Body.String())
	}
}

func TestControlJobPayloadIsNotExposedOverHTTP(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	ctx := t.Context()
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	id := itoa(accounts[0].ID)
	_, token, err := st.CreateAPIKey(ctx, "control", []string{"instance:control"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"X-API-Key": token}
	first := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+id+"/actions/start", `{}`, nil, headers)
	second := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+id+"/actions/start", `{}`, nil, headers)
	if first.Code != http.StatusAccepted || second.Code != http.StatusAccepted {
		t.Fatalf("start status first=%d second=%d", first.Code, second.Code)
	}
	var firstJob, secondJob domain.Job
	if err = json.Unmarshal(first.Body.Bytes(), &firstJob); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(second.Body.Bytes(), &secondJob); err != nil {
		t.Fatal(err)
	}
	if firstJob.ID == "" || firstJob.ID != secondJob.ID {
		t.Fatalf("same-minute start should reuse job, first=%#v second=%#v", firstJob, secondJob)
	}
	got := doRequest(t, handler, http.MethodGet, "/api/v1/jobs/"+firstJob.ID, "", nil, headers)
	if got.Code != http.StatusOK {
		t.Fatalf("job status = %d body = %s", got.Code, got.Body.String())
	}
	body := got.Body.String()
	if strings.Contains(body, "手动") || strings.Contains(body, `"payload"`) || strings.Contains(body, "source") {
		t.Fatalf("job JSON leaked control payload: %s", body)
	}
}

func TestPublicEndpointsHideDatabaseErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler := testAPIHandler(t, st)
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	leak := dir
	ready := doRequest(t, handler, http.MethodGet, "/readyz", "", nil, nil)
	if ready.Code != http.StatusServiceUnavailable || strings.Contains(ready.Body.String(), leak) || strings.Contains(strings.ToLower(ready.Body.String()), "sqlite") {
		t.Fatalf("readyz leaked internals: status=%d body=%s", ready.Code, ready.Body.String())
	}
	init := doRequest(t, handler, http.MethodGet, "/api/v1/system/init-status", "", nil, nil)
	if init.Code != http.StatusInternalServerError || strings.Contains(init.Body.String(), leak) || strings.Contains(strings.ToLower(init.Body.String()), "sqlite") {
		t.Fatalf("init-status leaked internals: status=%d body=%s", init.Code, init.Body.String())
	}
	login := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"x"}`, nil, nil)
	if login.Code != http.StatusInternalServerError || strings.Contains(login.Body.String(), leak) || strings.Contains(strings.ToLower(login.Body.String()), "sqlite") {
		t.Fatalf("login leaked internals: status=%d body=%s", login.Code, login.Body.String())
	}
	health := doRequest(t, handler, http.MethodGet, "/healthz", "", nil, nil)
	if health.Code != http.StatusOK {
		t.Fatalf("healthz status = %d body = %s", health.Code, health.Body.String())
	}
}

func TestLogsRequireAdminAndRejectUnknownControl(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	ctx := t.Context()
	accounts, err := st.ListAccounts(ctx)
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	_, widgetToken, err := st.CreateAPIKey(ctx, "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, controlToken, err := st.CreateAPIKey(ctx, "control", []string{"instance:control"}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ok := doRequest(t, handler, http.MethodGet, "/api/v1/logs", "", []*http.Cookie{session, csrf}, nil)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), `"logs"`) {
		t.Fatalf("admin logs status = %d body = %s", ok.Code, ok.Body.String())
	}
	widget := doRequest(t, handler, http.MethodGet, "/api/v1/logs", "", nil, map[string]string{"X-API-Key": widgetToken})
	if widget.Code != http.StatusForbidden {
		t.Fatalf("widget logs status = %d body = %s", widget.Code, widget.Body.String())
	}
	control := doRequest(t, handler, http.MethodGet, "/api/v1/logs", "", nil, map[string]string{"X-API-Key": controlToken})
	if control.Code != http.StatusForbidden {
		t.Fatalf("control logs status = %d body = %s", control.Code, control.Body.String())
	}
	reboot := doRequest(t, handler, http.MethodPost, "/api/v1/accounts/"+itoa(accounts[0].ID)+"/actions/reboot", `{}`, nil, map[string]string{"X-API-Key": controlToken})
	if reboot.Code != http.StatusBadRequest || !strings.Contains(reboot.Body.String(), "invalid_action") {
		t.Fatalf("reboot status = %d body = %s", reboot.Code, reboot.Body.String())
	}
}

func TestSetupHidesDatabaseErrors(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	handler := testAPIHandler(t, st)
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	setup := doRequest(t, handler, http.MethodPost, "/api/v1/setup", `{"admin_password":"Strong-Password-42!","traffic_threshold":95,"shutdown_mode":"KeepCharging","threshold_action":"stop_and_notify","api_interval":600,"timezone":"Asia/Shanghai"}`, nil, nil)
	if setup.Code != http.StatusBadRequest || !strings.Contains(setup.Body.String(), "setup_failed") || !strings.Contains(setup.Body.String(), "系统初始化失败") {
		t.Fatalf("setup status = %d body = %s", setup.Code, setup.Body.String())
	}
	if leakedInternalError(setup.Body.String(), dir) {
		t.Fatalf("setup leaked internals: %s", setup.Body.String())
	}
}

func TestStoreValidationErrorsStayPublic(t *testing.T) {
	rec := httptest.NewRecorder()
	writeStoreValidationError(rec, "config_failed", "配置保存失败", errors.New("invalid timezone"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid timezone") {
		t.Fatalf("validation status = %d body = %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	writeStoreValidationError(rec, "config_failed", "配置保存失败", errors.New("sqlite: database is closed"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "配置保存失败") || leakedInternalError(rec.Body.String(), "") {
		t.Fatalf("internal status = %d body = %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	writeStoreValidationError(rec, "config_failed", "配置保存失败", errors.New("account LTAItest is missing access key secret"))
	if !strings.Contains(rec.Body.String(), "missing access key secret") {
		t.Fatalf("missing secret status = %d body = %s", rec.Code, rec.Body.String())
	}
}

func leakedInternalError(body, path string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "sqlite") || strings.Contains(lower, "sql:") || strings.Contains(lower, "no such") {
		return true
	}
	return path != "" && strings.Contains(body, path)
}

func TestAuthenticatedEndpointsHideDatabaseErrors(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	cookies := []*http.Cookie{session, csrf}
	for _, path := range []string{"/api/v1/status", "/api/v1/config", "/api/v1/logs"} {
		response := doRequest(t, handler, http.MethodGet, path, "", cookies, nil)
		if response.Code != http.StatusInternalServerError && response.Code != http.StatusUnauthorized {
			t.Fatalf("%s status = %d body = %s", path, response.Code, response.Body.String())
		}
		body := strings.ToLower(response.Body.String())
		if strings.Contains(body, "sqlite") || strings.Contains(body, "no such") || strings.Contains(body, "sql:") {
			t.Fatalf("%s leaked internals: %s", path, response.Body.String())
		}
	}
}

func TestLoginSuccessClearsFailureLockout(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	for i := 0; i < 4; i++ {
		response := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong-password-xx"}`, nil, nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("pre-success attempt %d status = %d", i+1, response.Code)
		}
	}
	ok := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"`+testAdminPassword+`"}`, nil, nil)
	if ok.Code != http.StatusOK {
		t.Fatalf("success status = %d body = %s", ok.Code, ok.Body.String())
	}
	for i := 0; i < 2; i++ {
		response := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong-password-xx"}`, nil, nil)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("post-success attempt %d should not be locked, status = %d body = %s", i+1, response.Code, response.Body.String())
		}
	}
}

func TestWidgetSummaryOmitsSecretsAndStatusSupportsETag(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	_, token, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]string{"X-API-Key": token}
	summary := doRequest(t, handler, http.MethodGet, "/api/v1/widget/summary", "", nil, headers)
	if summary.Code != http.StatusOK {
		t.Fatalf("widget summary status = %d body = %s", summary.Code, summary.Body.String())
	}
	body := summary.Body.String()
	for _, secret := range []string{testAdminPassword, "super-secret-ak", "smtp-password-value", "telegram-token-value", "webhook-secret-value"} {
		if strings.Contains(body, secret) {
			t.Fatalf("widget summary leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, `"used"`) || !strings.Contains(body, `"total"`) {
		t.Fatalf("widget summary missing compact fields: %s", body)
	}

	status := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, headers)
	if status.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", status.Code, status.Body.String())
	}
	etag := status.Result().Header.Get("ETag")
	if etag == "" {
		t.Fatal("status missing ETag")
	}
	cached := doRequest(t, handler, http.MethodGet, "/api/v1/status", "", nil, map[string]string{"X-API-Key": token, "If-None-Match": etag})
	if cached.Code != http.StatusNotModified {
		t.Fatalf("etag status = %d body = %s", cached.Code, cached.Body.String())
	}
}

func TestTestNotificationRequiresAdminAndValidChannel(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	ok := doRequest(t, handler, http.MethodPost, "/api/v1/notifications/test/webhook", "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if ok.Code != http.StatusAccepted {
		t.Fatalf("admin test notify status = %d body = %s", ok.Code, ok.Body.String())
	}
	invalid := doRequest(t, handler, http.MethodPost, "/api/v1/notifications/test/sms", "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid channel status = %d body = %s", invalid.Code, invalid.Body.String())
	}
	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := doRequest(t, handler, http.MethodPost, "/api/v1/notifications/test/webhook", "", nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget test notify status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestUpdateAdminPasswordKeepsCurrentSession(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	current, csrf := loginCookies(t, handler)
	other, err := st.CreateSession(t.Context(), "127.0.0.2", "other", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	missing := doRequest(t, handler, http.MethodPut, "/api/v1/admin/password", `{"current_password":"`+testAdminPassword+`","new_password":"Replacement-Password-84!"}`, []*http.Cookie{current, csrf}, nil)
	if missing.Code != http.StatusForbidden || !strings.Contains(missing.Body.String(), "csrf_failed") {
		t.Fatalf("missing CSRF status = %d body = %s", missing.Code, missing.Body.String())
	}
	wrong := doRequest(t, handler, http.MethodPut, "/api/v1/admin/password", `{"current_password":"wrong-password-xx","new_password":"Replacement-Password-84!"}`, []*http.Cookie{current, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong current status = %d body = %s", wrong.Code, wrong.Body.String())
	}
	short := doRequest(t, handler, http.MethodPut, "/api/v1/admin/password", `{"current_password":"`+testAdminPassword+`","new_password":"short"}`, []*http.Cookie{current, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if short.Code != http.StatusBadRequest || !strings.Contains(short.Body.String(), "invalid_password") {
		t.Fatalf("short password status = %d body = %s", short.Code, short.Body.String())
	}

	ok := doRequest(t, handler, http.MethodPut, "/api/v1/admin/password", `{"current_password":"`+testAdminPassword+`","new_password":"Replacement-Password-84!"}`, []*http.Cookie{current, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if ok.Code != http.StatusOK {
		t.Fatalf("password update status = %d body = %s", ok.Code, ok.Body.String())
	}
	still := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{current, csrf}, nil)
	if still.Code != http.StatusOK {
		t.Fatalf("current session after update status = %d body = %s", still.Code, still.Body.String())
	}
	otherCookie := &http.Cookie{Name: "cdt_session", Value: other}
	dropped := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{otherCookie}, nil)
	if dropped.Code != http.StatusUnauthorized {
		t.Fatalf("other session after update status = %d body = %s", dropped.Code, dropped.Body.String())
	}

	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := doRequest(t, handler, http.MethodPut, "/api/v1/admin/password", `{"current_password":"Replacement-Password-84!","new_password":"Another-Password-99!"}`, nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget password update status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestPasskeyBeginIgnoresSpoofedForwardedProto(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	request := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/auth/passkeys/begin", strings.NewReader(`{}`))
	request.RemoteAddr = "203.0.113.10:443"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "https_required") {
		t.Fatalf("spoofed proto status = %d body = %s", response.Code, response.Body.String())
	}
}

func TestLoginCookiesHonorTrustedProxyProto(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	loopback := loginAttempt(t, handler, testAdminPassword, "127.0.0.1:8080", "")
	session := cookieNamed(loopback.Result().Cookies(), "cdt_session")
	if loopback.Code != http.StatusOK || session == nil || !session.Secure {
		t.Fatalf("loopback proxy proto status = %d secure=%v", loopback.Code, session != nil && session.Secure)
	}
	private := loginAttempt(t, handler, testAdminPassword, "10.0.0.2:8080", "")
	session = cookieNamed(private.Result().Cookies(), "cdt_session")
	if private.Code != http.StatusOK || session == nil || session.Secure {
		t.Fatalf("private IP spoof must not set Secure cookies, status = %d secure=%v", private.Code, session != nil && session.Secure)
	}
	spoofed := loginAttempt(t, handler, testAdminPassword, "203.0.113.10:443", "")
	session = cookieNamed(spoofed.Result().Cookies(), "cdt_session")
	if spoofed.Code != http.StatusOK || session == nil || session.Secure {
		t.Fatalf("spoofed proto must not set Secure cookies, status = %d secure=%v", spoofed.Code, session != nil && session.Secure)
	}
}

func TestLoginCookiesHonorConfiguredTrustedProxies(t *testing.T) {
	t.Setenv("CDT_TRUSTED_PROXIES", "10.0.0.0/8")
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	secure := loginAttempt(t, handler, testAdminPassword, "10.0.0.2:8080", "")
	session := cookieNamed(secure.Result().Cookies(), "cdt_session")
	if secure.Code != http.StatusOK || session == nil || !session.Secure {
		t.Fatalf("allowlisted proxy proto status = %d secure=%v", secure.Code, session != nil && session.Secure)
	}
	otherPrivate := loginAttempt(t, handler, testAdminPassword, "192.168.1.10:8080", "")
	session = cookieNamed(otherPrivate.Result().Cookies(), "cdt_session")
	if otherPrivate.Code != http.StatusOK || session == nil || session.Secure {
		t.Fatalf("non-allowlisted private proxy must not set Secure cookies, status = %d secure=%v", otherPrivate.Code, session != nil && session.Secure)
	}
}

func TestPasskeyBeginIgnoresSpoofedForwardedProtoFromPrivateIP(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	request := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/auth/passkeys/begin", strings.NewReader(`{}`))
	request.RemoteAddr = "10.0.0.2:8080"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "https_required") {
		t.Fatalf("private IP spoofed proto status = %d body = %s", response.Code, response.Body.String())
	}
}

func TestTrustedProxyDefaultsToLoopback(t *testing.T) {
	if !trustedProxy("127.0.0.1") || !trustedProxy("::1") {
		t.Fatal("loopback must be trusted")
	}
	for _, ip := range []string{"10.0.0.2", "192.168.1.1", "172.16.0.8", "203.0.113.10", "not-an-ip"} {
		if trustedProxy(ip) {
			t.Fatalf("%s must not be trusted by default", ip)
		}
	}
}

func TestTrustedProxyAllowlistParsesCIDRsAndBareIPs(t *testing.T) {
	t.Setenv("CDT_TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.50, not-a-cidr")
	if !trustedProxy("10.1.2.3") {
		t.Fatal("10.0.0.0/8 should match 10.1.2.3")
	}
	if !trustedProxy("192.168.1.50") {
		t.Fatal("bare IP should match itself")
	}
	if trustedProxy("192.168.1.51") {
		t.Fatal("neighbor IP must stay untrusted")
	}
	if !trustedProxy("127.0.0.1") {
		t.Fatal("loopback must stay trusted when an allowlist is set")
	}
}

func TestPasskeyLoginRequiresHTTPS(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	request := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/auth/passkeys/begin", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "https_required") {
		t.Fatalf("insecure passkey login status = %d body = %s", response.Code, response.Body.String())
	}

	session, csrf := loginCookies(t, handler)
	reg := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/admin/passkeys/register/begin", strings.NewReader(`{"name":"laptop"}`))
	reg.Header.Set("Content-Type", "application/json")
	reg.Header.Set("X-CDT-CSRF", csrf.Value)
	reg.AddCookie(session)
	reg.AddCookie(csrf)
	regResponse := httptest.NewRecorder()
	handler.ServeHTTP(regResponse, reg)
	if regResponse.Code != http.StatusBadRequest || !strings.Contains(regResponse.Body.String(), "https_required") {
		t.Fatalf("insecure passkey register status = %d body = %s", regResponse.Code, regResponse.Body.String())
	}
}

func TestMissingJobIsNotFound(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	_, token, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	missing := doRequest(t, handler, http.MethodGet, "/api/v1/jobs/does-not-exist", "", nil, map[string]string{"X-API-Key": token})
	if missing.Code != http.StatusNotFound || !strings.Contains(missing.Body.String(), "job_not_found") {
		t.Fatalf("missing job status = %d body = %s", missing.Code, missing.Body.String())
	}
}

func TestLoginRejectsInvalidJSON(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	malformed := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":`, nil, nil)
	if malformed.Code != http.StatusBadRequest || !strings.Contains(malformed.Body.String(), "invalid_request") {
		t.Fatalf("malformed login status = %d body = %s", malformed.Code, malformed.Body.String())
	}
	if strings.Contains(malformed.Body.String(), "unexpected EOF") || strings.Contains(malformed.Body.String(), "looking for beginning") {
		t.Fatalf("login JSON error leaked parser details: %s", malformed.Body.String())
	}
	unknown := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"x","extra":true}`, nil, nil)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "invalid_request") {
		t.Fatalf("unknown field login status = %d body = %s", unknown.Code, unknown.Body.String())
	}
	if strings.Contains(unknown.Body.String(), "unknown field") {
		t.Fatalf("login JSON error leaked parser details: %s", unknown.Body.String())
	}
}

func TestHealthzAndInitStatusArePublic(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	health := doRequest(t, handler, http.MethodGet, "/healthz", "", nil, nil)
	if health.Code != http.StatusOK || !strings.Contains(health.Body.String(), `"ok"`) {
		t.Fatalf("healthz status = %d body = %s", health.Code, health.Body.String())
	}
	init := doRequest(t, handler, http.MethodGet, "/api/v1/system/init-status", "", nil, nil)
	if init.Code != http.StatusOK || !strings.Contains(init.Body.String(), `"initialized":true`) {
		t.Fatalf("init-status status = %d body = %s", init.Code, init.Body.String())
	}
}

func TestSystemInfoRequiresAdminAndHistoryRejectsBadIDs(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	anon := doRequest(t, handler, http.MethodGet, "/api/v1/system/info", "", nil, nil)
	if anon.Code != http.StatusUnauthorized {
		t.Fatalf("anon system info status = %d body = %s", anon.Code, anon.Body.String())
	}
	widget := doRequest(t, handler, http.MethodGet, "/api/v1/system/info", "", nil, map[string]string{"X-API-Key": widgetToken})
	if widget.Code != http.StatusForbidden {
		t.Fatalf("widget system info status = %d body = %s", widget.Code, widget.Body.String())
	}
	session, csrf := loginCookies(t, handler)
	info := doRequest(t, handler, http.MethodGet, "/api/v1/system/info", "", []*http.Cookie{session, csrf}, nil)
	if info.Code != http.StatusOK || !strings.Contains(info.Body.String(), `"version"`) {
		t.Fatalf("admin system info status = %d body = %s", info.Code, info.Body.String())
	}
	bad := doRequest(t, handler, http.MethodGet, "/api/v1/accounts/0/history", "", nil, map[string]string{"X-API-Key": widgetToken})
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "invalid_id") {
		t.Fatalf("id 0 history status = %d body = %s", bad.Code, bad.Body.String())
	}
	malformed := doRequest(t, handler, http.MethodGet, "/api/v1/accounts/abc/history", "", nil, map[string]string{"X-API-Key": widgetToken})
	if malformed.Code != http.StatusBadRequest || !strings.Contains(malformed.Body.String(), "invalid_id") {
		t.Fatalf("abc history status = %d body = %s", malformed.Code, malformed.Body.String())
	}
}

func TestHistoryDoesNotLeakOtherAccountTraffic(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	accounts, err := st.ListAccounts(t.Context())
	if err != nil || len(accounts) != 1 {
		t.Fatalf("accounts=%v err=%v", accounts, err)
	}
	now := time.Date(2026, 9, 8, 16, 0, 0, 0, time.UTC)
	if err = st.AddTrafficStats(t.Context(), accounts[0].ID, 11, now); err != nil {
		t.Fatal(err)
	}
	if err = st.AddTrafficStats(t.Context(), accounts[0].ID+99, 99, now); err != nil {
		t.Fatal(err)
	}
	_, token, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	own := doRequest(t, handler, http.MethodGet, "/api/v1/accounts/"+itoa(accounts[0].ID)+"/history", "", nil, map[string]string{"X-API-Key": token})
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), `"traffic":11`) {
		t.Fatalf("own history status = %d body = %s", own.Code, own.Body.String())
	}
	if strings.Contains(own.Body.String(), `"traffic":99`) {
		t.Fatalf("own history leaked other account: %s", own.Body.String())
	}
	missing := doRequest(t, handler, http.MethodGet, "/api/v1/accounts/3/history", "", nil, map[string]string{"X-API-Key": token})
	if missing.Code != http.StatusOK || !strings.Contains(missing.Body.String(), `"hourly":[]`) || strings.Contains(missing.Body.String(), `"traffic":11`) {
		t.Fatalf("missing history status = %d body = %s", missing.Code, missing.Body.String())
	}
}

func TestClearLogsRequiresAdminCSRF(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	if err := st.AddLog(t.Context(), "audit", "keep-me"); err != nil {
		t.Fatal(err)
	}
	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := doRequest(t, handler, http.MethodDelete, "/api/v1/logs", "", nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget clear logs status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
	session, csrf := loginCookies(t, handler)
	missing := doRequest(t, handler, http.MethodDelete, "/api/v1/logs?tab=action", "", []*http.Cookie{session, csrf}, nil)
	if missing.Code != http.StatusForbidden || !strings.Contains(missing.Body.String(), "csrf_failed") {
		t.Fatalf("clear logs CSRF status = %d body = %s", missing.Code, missing.Body.String())
	}
	ok := doRequest(t, handler, http.MethodDelete, "/api/v1/logs?tab=action", "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if ok.Code != http.StatusOK {
		t.Fatalf("admin clear logs status = %d body = %s", ok.Code, ok.Body.String())
	}
	listed := doRequest(t, handler, http.MethodGet, "/api/v1/logs?tab=action", "", []*http.Cookie{session, csrf}, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"logs":[]`) {
		t.Fatalf("cleared logs status = %d body = %s", listed.Code, listed.Body.String())
	}
}

func TestSaveConfigRejectsUnknownFieldsAndBadThreshold(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}

	unknown := doRequest(t, handler, http.MethodPut, "/api/v1/config", `{"traffic_threshold":80,"extra":true}`, cookies, headers)
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "invalid_request") {
		t.Fatalf("unknown field status = %d body = %s", unknown.Code, unknown.Body.String())
	}

	got := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", cookies, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get config status = %d body = %s", got.Code, got.Body.String())
	}
	var config domain.Config
	if err := json.Unmarshal(got.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	config.TrafficThreshold = 101
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	bad := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), cookies, headers)
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "config_failed") {
		t.Fatalf("threshold 101 status = %d body = %s", bad.Code, bad.Body.String())
	}

	config.TrafficThreshold = 80
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	ok := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), cookies, headers)
	if ok.Code != http.StatusOK {
		t.Fatalf("save config status = %d body = %s", ok.Code, ok.Body.String())
	}
	reload := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", cookies, nil)
	if reload.Code != http.StatusOK || !strings.Contains(reload.Body.String(), `"traffic_threshold":80`) {
		t.Fatalf("reloaded config status = %d body = %s", reload.Code, reload.Body.String())
	}
	if strings.Contains(reload.Body.String(), "super-secret-ak") {
		t.Fatalf("saved config leaked secret: %s", reload.Body.String())
	}

	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget save config status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestUnknownAPIIsJSONNotFound(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	anon := doRequest(t, handler, http.MethodGet, "/api/v1/does-not-exist", "", nil, nil)
	if anon.Code != http.StatusNotFound || !strings.Contains(anon.Body.String(), "not_found") {
		t.Fatalf("unknown api status = %d body = %s", anon.Code, anon.Body.String())
	}
}

func TestSaveConfigRejectsInvalidShutdownAndInterval(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	got := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", cookies, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get config status = %d body = %s", got.Code, got.Body.String())
	}
	var config domain.Config
	if err := json.Unmarshal(got.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	config.ShutdownMode = "ForceStop"
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	mode := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), cookies, headers)
	if mode.Code != http.StatusBadRequest || !strings.Contains(mode.Body.String(), "config_failed") {
		t.Fatalf("invalid shutdown status = %d body = %s", mode.Code, mode.Body.String())
	}
	config.ShutdownMode = "KeepCharging"
	config.APIInterval = 29
	raw, err = json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	interval := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), cookies, headers)
	if interval.Code != http.StatusBadRequest || !strings.Contains(interval.Body.String(), "config_failed") {
		t.Fatalf("interval 29 status = %d body = %s", interval.Code, interval.Body.String())
	}
}

func TestRecoverHidesPanicDetails(t *testing.T) {
	server := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler := server.recover(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("secret-panic-detail")
	}))
	request := httptest.NewRequest(http.MethodGet, "http://monitor.example.com/panic", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "internal_error") {
		t.Fatalf("panic status = %d body = %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "secret-panic-detail") {
		t.Fatalf("panic leaked: %s", response.Body.String())
	}
}

func TestInitStatusIsPublic(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	before := doRequest(t, testAPIHandler(t, st), http.MethodGet, "/api/v1/system/init-status", "", nil, nil)
	if before.Code != http.StatusOK || !strings.Contains(before.Body.String(), `"initialized":false`) {
		t.Fatalf("before setup status = %d body = %s", before.Code, before.Body.String())
	}
	after := doRequest(t, testAPIHandler(t, initializedAuthStore(t)), http.MethodGet, "/api/v1/system/init-status", "", nil, nil)
	if after.Code != http.StatusOK || !strings.Contains(after.Body.String(), `"initialized":true`) {
		t.Fatalf("after setup status = %d body = %s", after.Code, after.Body.String())
	}
}

func TestPasskeyCompleteRequiresLiveSession(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	expired := doRequest(t, handler, http.MethodPost, "/api/v1/admin/passkeys/register/complete?session_id=missing", `{}`, []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if expired.Code != http.StatusBadRequest || !strings.Contains(expired.Body.String(), "passkey_session_expired") {
		t.Fatalf("expired passkey complete status = %d body = %s", expired.Code, expired.Body.String())
	}
	listed := doRequest(t, handler, http.MethodGet, "/api/v1/admin/passkeys", "", []*http.Cookie{session, csrf}, nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"passkeys":[]`) {
		t.Fatalf("empty passkeys status = %d body = %s", listed.Code, listed.Body.String())
	}
	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := doRequest(t, handler, http.MethodGet, "/api/v1/admin/passkeys", "", nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget passkeys status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
}

func TestSaveConfigRejectsInvalidThresholdAction(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	got := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{session, csrf}, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get config status = %d body = %s", got.Code, got.Body.String())
	}
	var config domain.Config
	if err := json.Unmarshal(got.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	config.ThresholdAction = "stop_only"
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	bad := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "config_failed") {
		t.Fatalf("invalid threshold action status = %d body = %s", bad.Code, bad.Body.String())
	}
}

func TestHeartbeatLogsRequireAdmin(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	if err := st.AddLog(t.Context(), "heartbeat", "tick"); err != nil {
		t.Fatal(err)
	}
	_, widgetToken, err := st.CreateAPIKey(t.Context(), "widget", []string{"widget:read"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := doRequest(t, handler, http.MethodGet, "/api/v1/logs?tab=heartbeat", "", nil, map[string]string{"X-API-Key": widgetToken})
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("widget heartbeat logs status = %d body = %s", forbidden.Code, forbidden.Body.String())
	}
	session, csrf := loginCookies(t, handler)
	ok := doRequest(t, handler, http.MethodGet, "/api/v1/logs?tab=heartbeat", "", []*http.Cookie{session, csrf}, nil)
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), "tick") {
		t.Fatalf("admin heartbeat logs status = %d body = %s", ok.Code, ok.Body.String())
	}
	badID := doRequest(t, handler, http.MethodDelete, "/api/v1/admin/passkeys/0", "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if badID.Code != http.StatusBadRequest || !strings.Contains(badID.Body.String(), "invalid_id") {
		t.Fatalf("delete passkey 0 status = %d body = %s", badID.Code, badID.Body.String())
	}
}

func TestLoginRateLimitAfterEightAttempts(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	for i := 0; i < 8; i++ {
		response := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong-password-xx"}`, nil, nil)
		if i < 5 && response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body = %s", i+1, response.Code, response.Body.String())
		}
		if i >= 5 && i < 8 && (response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "login_locked")) {
			t.Fatalf("attempt %d expected lockout, status = %d body = %s", i+1, response.Code, response.Body.String())
		}
	}
	limited := doRequest(t, handler, http.MethodPost, "/api/v1/auth/login", `{"password":"wrong-password-xx"}`, nil, nil)
	if limited.Code != http.StatusTooManyRequests || !strings.Contains(limited.Body.String(), "rate_limited") {
		t.Fatalf("ninth attempt status = %d body = %s", limited.Code, limited.Body.String())
	}
}

func TestReadyzIsPublic(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	ready := doRequest(t, handler, http.MethodGet, "/readyz", "", nil, nil)
	if ready.Code != http.StatusOK || !strings.Contains(ready.Body.String(), `"ready"`) {
		t.Fatalf("readyz status = %d body = %s", ready.Code, ready.Body.String())
	}
}

func TestSaveConfigRejectsInvalidTimezone(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	got := doRequest(t, handler, http.MethodGet, "/api/v1/config", "", []*http.Cookie{session, csrf}, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get config status = %d body = %s", got.Code, got.Body.String())
	}
	var config domain.Config
	if err := json.Unmarshal(got.Body.Bytes(), &config); err != nil {
		t.Fatal(err)
	}
	config.Timezone = "Not/AZone"
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	bad := doRequest(t, handler, http.MethodPut, "/api/v1/config", string(raw), []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if bad.Code != http.StatusBadRequest || !strings.Contains(bad.Body.String(), "config_failed") {
		t.Fatalf("invalid timezone status = %d body = %s", bad.Code, bad.Body.String())
	}
}

func TestDeletePasskeyRequiresCSRF(t *testing.T) {
	st := initializedAuthStore(t)
	if err := st.SavePasskey(t.Context(), "laptop", webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte("public-key")}); err != nil {
		t.Fatal(err)
	}
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	listed := doRequest(t, handler, http.MethodGet, "/api/v1/admin/passkeys", "", []*http.Cookie{session, csrf}, nil)
	if listed.Code != http.StatusOK {
		t.Fatalf("list passkeys status = %d body = %s", listed.Code, listed.Body.String())
	}
	var payload struct {
		Passkeys []domain.Passkey `json:"passkeys"`
	}
	if err := json.Unmarshal(listed.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Passkeys) != 1 || payload.Passkeys[0].ID < 1 {
		t.Fatalf("passkeys = %#v", payload.Passkeys)
	}
	path := "/api/v1/admin/passkeys/" + itoa(payload.Passkeys[0].ID)
	missing := doRequest(t, handler, http.MethodDelete, path, "", []*http.Cookie{session, csrf}, nil)
	if missing.Code != http.StatusForbidden || !strings.Contains(missing.Body.String(), "csrf_failed") {
		t.Fatalf("missing CSRF status = %d body = %s", missing.Code, missing.Body.String())
	}
	ok := doRequest(t, handler, http.MethodDelete, path, "", []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if ok.Code != http.StatusOK || !strings.Contains(ok.Body.String(), `"success":true`) {
		t.Fatalf("delete passkey status = %d body = %s", ok.Code, ok.Body.String())
	}
	empty := doRequest(t, handler, http.MethodGet, "/api/v1/admin/passkeys", "", []*http.Cookie{session, csrf}, nil)
	if empty.Code != http.StatusOK || !strings.Contains(empty.Body.String(), `"passkeys":[]`) {
		t.Fatalf("after delete status = %d body = %s", empty.Code, empty.Body.String())
	}
}

func TestMutationsRejectInvalidJSON(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	cases := []struct {
		method, path, body string
	}{
		{http.MethodPost, "/api/v1/setup", `{"admin_password":`},
		{http.MethodPut, "/api/v1/config", `{"traffic_threshold":`},
		{http.MethodPut, "/api/v1/admin/password", `{"current_password":`},
		{http.MethodPost, "/api/v1/api-keys", `{"name":"widget","scopes":["widget:read"],"extra":true}`},
		{http.MethodPost, "/api/v1/admin/passkeys/register/begin", `{"name":`},
	}
	for _, tc := range cases {
		got := doRequest(t, handler, tc.method, tc.path, tc.body, cookies, headers)
		if got.Code != http.StatusBadRequest || !strings.Contains(got.Body.String(), "invalid_request") {
			t.Fatalf("%s %s status = %d body = %s", tc.method, tc.path, got.Code, got.Body.String())
		}
		if strings.Contains(got.Body.String(), "unexpected EOF") || strings.Contains(got.Body.String(), "unknown field") {
			t.Fatalf("%s %s leaked parser details: %s", tc.method, tc.path, got.Body.String())
		}
	}
}
