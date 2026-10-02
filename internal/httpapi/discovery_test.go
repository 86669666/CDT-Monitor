package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wang4386/CDT-Monitor/internal/aliyun"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/engine"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

type discoveryFake struct {
	aliyun.Provider
	calls    int
	account  domain.Account
	secret   string
	err      error
	deadline time.Time
}

func (p *discoveryFake) DiscoverInstances(ctx context.Context, a domain.Account, secret, token string) (aliyun.DiscoveryPage, error) {
	p.calls++
	p.account = a
	p.secret = secret
	p.deadline, _ = ctx.Deadline()
	return aliyun.DiscoveryPage{Instances: []aliyun.DiscoveredInstance{{InstanceID: "i-found", InstanceName: "Web", RegionID: a.RegionID, Status: "Running", ChargeType: "spot"}}, NextToken: ""}, p.err
}

func TestDiscoveryAuthCredentialBindingAndNoWrites(t *testing.T) {
	st := initializedAuthStore(t)
	p := &discoveryFake{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server := New(st, engine.New(st, p, nil, logger, 1), fstest.MapFS{"index.html": {Data: []byte("ok")}}, logger)
	h := server.Handler()
	session, csrf := loginCookies(t, h)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	body := `{"source_account_id":1,"access_key_id":"LTAItest","region_id":"cn-beijing"}`
	if got := doRequest(t, h, "POST", "/api/v1/accounts/discover", body, nil, nil); got.Code != 401 {
		t.Fatal(got.Code)
	}
	if got := doRequest(t, h, "POST", "/api/v1/accounts/discover", body, cookies, nil); got.Code != 403 {
		t.Fatal(got.Code)
	}
	_, key, err := st.CreateAPIKey(t.Context(), "test", []string{"instance:control", "widget:read", "cron:run"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := doRequest(t, h, "POST", "/api/v1/accounts/discover", body, nil, map[string]string{"X-API-Key": key}); got.Code != 403 {
		t.Fatal(got.Code)
	}
	for _, bad := range []string{
		`{"source_account_id":1,"access_key_id":"LTAIwrong","region_id":"cn-beijing"}`,
		`{"source_account_id":1,"access_key_id":"LTAItest","access_key_secret":"mixed","region_id":"cn-beijing"}`,
		`{"source_account_id":999,"access_key_id":"LTAItest","region_id":"cn-beijing"}`,
		`{"source_account_id":1,"access_key_id":"LTAItest","region_id":"bad/region"}`,
		`{"source_account_id":1,"access_key_id":"LTAItest","region_id":"cn-beijing","host":"attacker"}`,
	} {
		if got := doRequest(t, h, "POST", "/api/v1/accounts/discover", bad, cookies, headers); got.Code != 400 {
			t.Fatalf("%d %s", got.Code, got.Body.String())
		}
	}
	if p.calls != 0 {
		t.Fatal("rejected requests reached provider")
	}
	before, _ := st.GetConfig(t.Context())
	got := doRequest(t, h, "POST", "/api/v1/accounts/discover", body, cookies, headers)
	if got.Code != 200 || p.calls != 1 || p.secret != "super-secret-ak" || p.account.AccessKeyID != "LTAItest" {
		t.Fatal("saved credential query failed")
	}
	if strings.Contains(got.Body.String(), p.secret) || strings.Contains(got.Body.String(), "LTAItest") {
		t.Fatal("credential leaked")
	}
	if d := time.Until(p.deadline); d <= 0 || d > 25*time.Second {
		t.Fatal("missing request deadline")
	}
	var value any
	_ = json.Unmarshal(got.Body.Bytes(), &value)
	spec := readOpenAPI(t)
	schema := spec.Paths["/api/v1/accounts/discover"]["post"].Responses["200"].Content["application/json"].Schema
	if err := spec.responseShape(schema, value, "discovery"); err != nil {
		t.Fatal(err)
	}
	manual := `{"access_key_id":"LTAInew","access_key_secret":"fresh-secret","region_id":"cn-hongkong"}`
	got = doRequest(t, h, "POST", "/api/v1/accounts/discover", manual, cookies, headers)
	if got.Code != 200 || p.secret != "fresh-secret" || p.account.AccessKeyID != "LTAInew" {
		t.Fatal("new credential mode failed")
	}
	p.err = errors.New("LTAInew fresh-secret full provider error")
	got = doRequest(t, h, "POST", "/api/v1/accounts/discover", manual, cookies, headers)
	if got.Code != 502 || strings.Contains(got.Body.String(), "fresh-secret") || strings.Contains(got.Body.String(), "LTAInew") {
		t.Fatal("provider error leaked")
	}
	after, _ := st.GetConfig(t.Context())
	if !reflect.DeepEqual(before, after) {
		t.Fatal("discovery mutated configuration")
	}
	jobs, err := st.CountQueuedJobs(t.Context())
	if err != nil || jobs != 0 {
		t.Fatal("discovery enqueued work")
	}
	if secret, err := st.AccountSecretForKey(t.Context(), 1, "LTAIwrong"); err == nil || secret != "" {
		t.Fatal("identity mismatch accepted")
	}
	// The old expected key must fail after a stored credential is changed.
	after.Accounts[0].AccessKeyID = "LTAIreplacement"
	after.Accounts[0].AccessKeySecret = "replacement-secret"
	if err := st.SaveConfig(t.Context(), after); err != nil {
		t.Fatal(err)
	}
	got = doRequest(t, h, "POST", "/api/v1/accounts/discover", body, cookies, headers)
	if got.Code != 400 {
		t.Fatal("stale credential reference accepted")
	}
}
