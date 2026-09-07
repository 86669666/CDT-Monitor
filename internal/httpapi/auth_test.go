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
