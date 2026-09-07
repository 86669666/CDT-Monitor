package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/engine"
	"github.com/wang4386/CDT-Monitor/internal/notify"
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
	if !config.Notifications.Webhook.SecretConfigured || config.Notifications.Webhook.Secret != "" || config.Notifications.Webhook.Headers != "" {
		t.Fatalf("webhook secret flags = %#v", config.Notifications.Webhook)
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
	request := httptest.NewRequest(http.MethodPost, "https://monitor.example.com/api/v1/auth/login", strings.NewReader(`{"password":"`+password+`"}`))
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
