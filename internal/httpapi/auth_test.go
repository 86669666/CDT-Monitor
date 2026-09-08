package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"

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

func TestCreateAPIKeyRejectsPastExpiryHTTP(t *testing.T) {
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st)
	session, csrf := loginCookies(t, handler)
	past := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	created := doRequest(t, handler, http.MethodPost, "/api/v1/api-keys", `{"name":"old","scopes":["widget:read"],"expires_at":"`+past+`"}`, []*http.Cookie{session, csrf}, map[string]string{"X-CDT-CSRF": csrf.Value})
	if created.Code != http.StatusBadRequest || !strings.Contains(created.Body.String(), "api_key_failed") {
		t.Fatalf("past expiry status = %d body = %s", created.Code, created.Body.String())
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
