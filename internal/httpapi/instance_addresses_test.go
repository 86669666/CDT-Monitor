package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInstanceAddressesRequireAdminAndReadOnlyCache(t *testing.T) {
	st := initializedAuthStore(t)
	h := testAPIHandler(t, st) // nil provider and no running workers
	account, err := st.GetAccount(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(account.AccessKeyID + "\x00" + account.RegionID + "\x00" + account.InstanceID))
	cache := map[string]any{"identity": hex.EncodeToString(sum[:]), "kind": "spot", "observed_at": time.Now().UTC(), "public_ipv4": "203.0.113.7", "ipv6": "2001:db8::1", "addresses_observed_at": time.Now().UTC()}
	if err = st.SetBillingCache(t.Context(), account.ID, "instance_metadata", "", cache); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/accounts/instance-addresses"
	if got := doRequest(t, h, "GET", path, "", nil, nil); got.Code != http.StatusUnauthorized {
		t.Fatal(got.Code)
	}
	_, key, err := st.CreateAPIKey(t.Context(), "all-scopes", []string{"widget:read", "instance:control", "cron:run"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := doRequest(t, h, "GET", path, "", nil, map[string]string{"X-API-Key": key}); got.Code != http.StatusForbidden {
		t.Fatal(got.Code)
	}
	session, csrf := loginCookies(t, h)
	cookies := []*http.Cookie{session, csrf}
	got := doRequest(t, h, "GET", path, "", cookies, nil)
	if got.Code != http.StatusOK || got.Header().Get("Cache-Control") != "no-store" || !strings.Contains(got.Body.String(), "203.0.113.7") || !strings.Contains(got.Body.String(), "2001:db8::1") {
		t.Fatalf("admin cache response status=%d", got.Code)
	}
	for _, url := range []string{"/api/v1/status", "/api/v1/widget/summary"} {
		response := doRequest(t, h, "GET", url, "", nil, map[string]string{"X-API-Key": key})
		if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "203.0.113.7") || strings.Contains(response.Body.String(), "2001:db8::1") {
			t.Fatalf("address leaked to %s", url)
		}
	}
	jobs, err := st.CountQueuedJobs(t.Context())
	if err != nil || jobs != 0 {
		t.Fatal("address GET enqueued a job")
	}
	// An unrelated broken notification secret must not be decrypted by this read.
	if _, err := st.DB().ExecContext(t.Context(), `INSERT INTO settings(key,value) VALUES('notify_password','enc:v2:invalid') ON CONFLICT(key) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	if got := doRequest(t, h, "GET", path, "", cookies, nil); got.Code != http.StatusOK {
		t.Fatalf("address endpoint read unrelated notification secrets: %d", got.Code)
	}
}
