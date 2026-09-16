package httpapi

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/engine"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

func TestSecurityHeadersAllowFaviconEndpoint(t *testing.T) {
	server := &Server{}
	handler := server.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://monitor.example.com/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	csp := response.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' data: https://a.favicon.im") {
		t.Fatalf("favicon endpoint missing from CSP: %s", csp)
	}
	if !strings.Contains(csp, "connect-src 'self' https://api.github.com") {
		t.Fatalf("GitHub API endpoint missing from CSP: %s", csp)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q", response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Fatalf("CORP = %q", response.Header().Get("Cross-Origin-Resource-Policy"))
	}
	if response.Header().Get("Cross-Origin-Opener-Policy") != "same-origin" {
		t.Fatalf("COOP = %q", response.Header().Get("Cross-Origin-Opener-Policy"))
	}
}

func TestBeginPasskeyLoginIncludesRegisteredCredentialIDs(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	credentialID := []byte("desktop-bitwarden-credential")
	if err = st.SavePasskey(t.Context(), "PC Bitwarden", webauthn.Credential{ID: credentialID, PublicKey: []byte("test-key")}); err != nil {
		t.Fatal(err)
	}

	server := &Server{store: st, limits: make(map[string]*rateWindow), passkeys: make(map[string]passkeySession)}
	request := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/auth/passkeys/begin", strings.NewReader(`{}`))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	server.beginPasskeyLogin(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		SessionID string `json:"session_id"`
		PublicKey struct {
			PublicKey struct {
				AllowCredentials []struct {
					ID string `json:"id"`
				} `json:"allowCredentials"`
			} `json:"publicKey"`
		} `json:"public_key"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.PublicKey.PublicKey.AllowCredentials) != 1 || payload.PublicKey.PublicKey.AllowCredentials[0].ID != base64.RawURLEncoding.EncodeToString(credentialID) {
		t.Fatalf("allowCredentials = %#v", payload.PublicKey.PublicKey.AllowCredentials)
	}
	ceremony, ok := server.passkeys[payload.SessionID]
	if !ok || string(ceremony.session.UserID) != adminWebAuthnID {
		t.Fatalf("login session does not identify the admin user: %#v", ceremony.session.UserID)
	}
}

func TestBeginPasskeyLoginIgnoresSpoofedForwardedHost(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err = st.SavePasskey(t.Context(), "laptop", webauthn.Credential{ID: []byte("credential-id"), PublicKey: []byte("public-key")}); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: st, limits: make(map[string]*rateWindow), passkeys: make(map[string]passkeySession)}

	spoofed := httptest.NewRequest(http.MethodPost, "https://monitor.example.com/api/v1/auth/passkeys/begin", strings.NewReader(`{}`))
	spoofed.RemoteAddr = "203.0.113.10:443"
	spoofed.TLS = &tls.ConnectionState{}
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	spoofed.Header.Set("X-Forwarded-Host", "attacker.example")
	spoofedResponse := httptest.NewRecorder()
	server.beginPasskeyLogin(spoofedResponse, spoofed)
	if spoofedResponse.Code != http.StatusOK {
		t.Fatalf("spoofed host status = %d body = %s", spoofedResponse.Code, spoofedResponse.Body.String())
	}
	if rpID := passkeyRPID(t, spoofedResponse.Body.Bytes()); rpID != "monitor.example.com" {
		t.Fatalf("spoofed X-Forwarded-Host changed RPID to %q", rpID)
	}

	proxied := httptest.NewRequest(http.MethodPost, "https://127.0.0.1/api/v1/auth/passkeys/begin", strings.NewReader(`{}`))
	proxied.RemoteAddr = "127.0.0.1:8080"
	proxied.Header.Set("X-Forwarded-Proto", "https")
	proxied.Header.Set("X-Forwarded-Host", "cdt.internal")
	proxiedResponse := httptest.NewRecorder()
	server.beginPasskeyLogin(proxiedResponse, proxied)
	if proxiedResponse.Code != http.StatusOK {
		t.Fatalf("proxied host status = %d body = %s", proxiedResponse.Code, proxiedResponse.Body.String())
	}
	if rpID := passkeyRPID(t, proxiedResponse.Body.Bytes()); rpID != "cdt.internal" {
		t.Fatalf("trusted proxy host RPID = %q", rpID)
	}
}

func passkeyRPID(t *testing.T, body []byte) string {
	t.Helper()
	var payload struct {
		PublicKey struct {
			PublicKey struct {
				RPID string `json:"rpId"`
			} `json:"publicKey"`
		} `json:"public_key"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatal(err)
	}
	return payload.PublicKey.PublicKey.RPID
}

func TestBeginPasskeyLoginRejectsEmptyCredentialList(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	server := &Server{store: st, limits: make(map[string]*rateWindow), passkeys: make(map[string]passkeySession)}
	request := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/auth/passkeys/begin", strings.NewReader(`{}`))
	request.TLS = &tls.ConnectionState{}
	request.Header.Set("X-Forwarded-Proto", "https")
	response := httptest.NewRecorder()
	server.beginPasskeyLogin(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
}

func TestRefreshAllEnqueuesEveryConfiguredAccount(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	config := domain.Config{
		AdminPassword: "Strong-Password-42!", TrafficThreshold: 95, ShutdownMode: "KeepCharging", ThresholdAction: "stop_and_notify", APIInterval: 600, Timezone: "Asia/Shanghai",
		Accounts: []domain.Account{
			{AccessKeyID: "LTAItest-one", AccessKeySecret: "secret-one", RegionID: "cn-hongkong", InstanceID: "i-one", MaxTraffic: 200, SiteType: "china"},
			{AccessKeyID: "LTAItest-two", AccessKeySecret: "secret-two", RegionID: "ap-southeast-1", InstanceID: "i-two", MaxTraffic: 300, SiteType: "international"},
		},
	}
	if err = st.Setup(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	eng := engine.New(st, nil, nil, slog.Default(), 1)
	server := &Server{store: st, engine: eng}
	request := httptest.NewRequest(http.MethodPost, "http://monitor.example.com/api/v1/accounts/refresh", strings.NewReader(`{}`))
	response := httptest.NewRecorder()
	server.refreshAll(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Jobs []domain.Job `json:"jobs"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Jobs) != 2 {
		t.Fatalf("jobs = %#v", payload.Jobs)
	}
	if payload.Jobs[0].Type != engine.JobRefreshAccount || payload.Jobs[1].Type != engine.JobRefreshAccount || payload.Jobs[0].AccountID == payload.Jobs[1].AccountID {
		t.Fatalf("unexpected refresh jobs: %#v", payload.Jobs)
	}
}

func TestFetchLatestReleaseDoesNotFollowRedirects(t *testing.T) {
	hit := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hit = true
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()

	original := githubHTTPClient
	githubHTTPClient = &http.Client{
		Timeout:       original.Timeout,
		CheckRedirect: original.CheckRedirect,
	}
	t.Cleanup(func() { githubHTTPClient = original })

	_, err := fetchLatestRelease(context.Background(), "test", source.URL)
	if !errors.Is(err, errGitHubRedirect) {
		t.Fatalf("err=%v", err)
	}
	if hit {
		t.Fatal("github release check followed a redirect")
	}
}

func TestFetchLatestReleaseReadsTag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("accept = %q", r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.3"}`))
	}))
	defer server.Close()
	original := githubHTTPClient
	githubHTTPClient = server.Client()
	githubHTTPClient.CheckRedirect = original.CheckRedirect
	t.Cleanup(func() { githubHTTPClient = original })

	got, err := fetchLatestRelease(context.Background(), "test", server.URL)
	if err != nil || got != "v1.2.3" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestGitHubHTTPClientRequiresTLS12(t *testing.T) {
	transport, ok := githubHTTPClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("github transport TLS = %#v", githubHTTPClient.Transport)
	}
	if transport.DialContext == nil {
		t.Fatal("github HTTP dialer must pin destinations at connect time")
	}
}

func TestGitHubDialContextRejectsMetadataIP(t *testing.T) {
	_, err := githubDialContext(context.Background(), "tcp", net.JoinHostPort("169.254.169.254", "443"))
	if !errors.Is(err, errGitHubForbiddenHost) {
		t.Fatalf("link-local dial err=%v", err)
	}
	_, err = githubDialContext(context.Background(), "tcp", net.JoinHostPort("100.100.100.200", "443"))
	if !errors.Is(err, errGitHubForbiddenHost) {
		t.Fatalf("aliyun metadata dial err=%v", err)
	}
}

func TestAllowRateExpiresStaleWindows(t *testing.T) {
	server := &Server{limits: make(map[string]*rateWindow)}
	if !server.allowRate("login:1.1.1.1", 1, time.Hour) {
		t.Fatal("first attempt should pass")
	}
	if server.allowRate("login:1.1.1.1", 1, time.Hour) {
		t.Fatal("same-window excess should be limited")
	}
	server.limits["login:1.1.1.1"].expires = time.Now().Add(-time.Second)
	server.limits["setup:2.2.2.2"] = &rateWindow{start: time.Now().Add(-time.Hour), count: 9, expires: time.Now().Add(-time.Second)}
	if !server.allowRate("login:1.1.1.1", 1, time.Hour) {
		t.Fatal("expired window should reset")
	}
	if _, ok := server.limits["setup:2.2.2.2"]; ok {
		t.Fatal("stale rate window must be collected")
	}
	if len(server.limits) != 1 {
		t.Fatalf("limits = %#v", server.limits)
	}
}

func TestSavePasskeySessionCapsLiveCeremonies(t *testing.T) {
	server := &Server{passkeys: make(map[string]passkeySession)}
	ids := []string{"a", "b", "c", "d", "e", "f", "g", "h"}
	for _, id := range ids {
		if !server.savePasskeySession(id, passkeySession{kind: "login", expires: time.Now().Add(time.Minute)}) {
			t.Fatalf("session %s rejected before cap", id)
		}
	}
	if server.savePasskeySession("overflow", passkeySession{kind: "login", expires: time.Now().Add(time.Minute)}) {
		t.Fatal("expected passkey ceremony cap")
	}
	session := server.passkeys["a"]
	session.expires = time.Now().Add(-time.Second)
	server.passkeys["a"] = session
	if !server.savePasskeySession("after-expire", passkeySession{kind: "login", expires: time.Now().Add(time.Minute)}) {
		t.Fatal("expired ceremony should free a slot")
	}
	if _, ok := server.passkeys["a"]; ok {
		t.Fatal("expired ceremony must be collected")
	}
	if len(server.passkeys) != maxPasskeySessions {
		t.Fatalf("passkeys = %d", len(server.passkeys))
	}
}
