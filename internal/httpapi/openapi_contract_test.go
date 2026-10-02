package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/wang4386/CDT-Monitor/internal/domain"
	"github.com/wang4386/CDT-Monitor/internal/engine"
	"github.com/wang4386/CDT-Monitor/internal/store"
)

type openAPIContract struct {
	Paths map[string]map[string]struct {
		OperationID string                `json:"operationId"`
		Security    []map[string][]string `json:"security"`
		Scopes      []string              `json:"x-api-key-scopes"`
		Responses   map[string]struct {
			Codes   []string `json:"x-error-codes"`
			Content map[string]struct {
				Schema map[string]any `json:"schema"`
			} `json:"content"`
		} `json:"responses"`
	} `json:"paths"`
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

func readOpenAPI(t *testing.T) openAPIContract {
	t.Helper()
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec openAPIContract
	if err = json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("contract must use JSON-compatible YAML: %v", err)
	}
	return spec
}

// AST inspection catches every explicit registration, including additions using
// methods that the lightweight Python inventory may not yet recognize.
func TestOpenAPIRouteCoverageAndSecurity(t *testing.T) {
	spec := readOpenAPI(t)
	file, err := parser.ParseFile(token.NewFileSet(), "server.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc") {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok || receiver.Name != "mux" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok {
			t.Fatal("non-literal mux route requires updating contract inventory")
		}
		pattern, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		if pattern == "/" { // Static fallback is intentionally excluded.
			return true
		}
		method, path, ok := strings.Cut(pattern, " ")
		if !ok {
			t.Fatalf("unexpected route pattern %q", pattern)
		}
		op, ok := spec.Paths[path][strings.ToLower(method)]
		if !ok {
			t.Errorf("undocumented route %s", pattern)
			return true
		}
		seen[pattern] = true
		var handler string
		var scopes []string
		ast.Inspect(call.Args[1], func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "s" && sel.Sel.Name != "require" && sel.Sel.Name != "requireAny" {
					handler = sel.Sel.Name
				}
			}
			if nested, ok := n.(*ast.CallExpr); ok {
				if sel, ok := nested.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "require" || sel.Sel.Name == "requireAny") {
					ast.Inspect(nested.Args[0], func(n ast.Node) bool {
						if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
							value, _ := strconv.Unquote(lit.Value)
							scopes = append(scopes, value)
						}
						return true
					})
				}
			}
			return true
		})
		if op.OperationID != handler {
			t.Errorf("%s operationId=%q, handler=%q", pattern, op.OperationID, handler)
		}
		expected := []map[string][]string{}
		keyScopes := []string{}
		if len(scopes) > 0 {
			session := map[string][]string{"Session": {}}
			if method != "GET" && method != "HEAD" {
				session["CSRFCookie"], session["CSRFHeader"] = []string{}, []string{}
			}
			expected = append(expected, session)
			if scopes[0] != "admin" {
				keyScopes = scopes
				expected = append(expected, map[string][]string{"BearerKey": {}}, map[string][]string{"HeaderKey": {}})
			}
		}
		if handler == "legacyMonitor" {
			expected = []map[string][]string{{"BearerKey": {}}, {"HeaderKey": {}}, {"LegacyQueryKey": {}}}
			keyScopes = []string{"cron:run"}
		}
		if !reflect.DeepEqual(op.Security, expected) {
			t.Errorf("%s security differs from route middleware: got %v, want %v", pattern, op.Security, expected)
		}
		if len(keyScopes) != len(op.Scopes) || strings.Join(keyScopes, ",") != strings.Join(op.Scopes, ",") {
			t.Errorf("%s API Key scopes=%v, want %v", pattern, op.Scopes, keyScopes)
		}
		return true
	})
	for path, methods := range spec.Paths {
		for method := range methods {
			if !seen[strings.ToUpper(method)+" "+path] {
				t.Errorf("contract documents unregistered route %s %s", method, path)
			}
		}
	}
	t.Logf("covered %d explicit operations; implicit HEAD follows GET", len(seen))
}

func TestOpenAPIDomainFieldCoverage(t *testing.T) {
	spec := readOpenAPI(t)
	models := []any{domain.Config{}, domain.Account{}, domain.EmailConfig{}, domain.TelegramConfig{}, domain.WebhookConfig{}, domain.NotificationConfig{}, domain.AccountSummary{}, domain.Job{}, domain.APIKey{}, domain.Passkey{}, domain.LogEntry{}, domain.TrafficPoint{}, domain.History{}}
	for _, model := range models {
		typ := reflect.TypeOf(model)
		schema := spec.Components.Schemas[typ.Name()]
		properties, ok := schema["properties"].(map[string]any)
		if !ok {
			t.Fatalf("missing schema %s", typ.Name())
		}
		expected := map[string]bool{}
		var required []string
		for i := 0; i < typ.NumField(); i++ {
			parts := strings.Split(typ.Field(i).Tag.Get("json"), ",")
			if parts[0] == "-" {
				continue
			}
			expected[parts[0]] = true
			if len(parts) == 1 {
				required = append(required, parts[0])
			}
			if _, ok := properties[parts[0]]; !ok {
				t.Errorf("%s missing JSON field %s", typ.Name(), parts[0])
			}
		}
		for field := range properties {
			if !expected[field] {
				t.Errorf("%s invents JSON field %s", typ.Name(), field)
			}
		}
		var actual []string
		for _, field := range schema["required"].([]any) {
			actual = append(actual, field.(string))
		}
		sort.Strings(actual)
		sort.Strings(required)
		if !reflect.DeepEqual(actual, required) {
			t.Errorf("%s required fields differ from Go JSON tags", typ.Name())
		}
	}
}

// This checks the shape/required/type/enum/const/format/writeOnly subset used by
// response schemas. Full OpenAPI structural validation lives in check-openapi.py.
func (spec openAPIContract) responseShape(schema map[string]any, value any, path string) error {
	if pointer, ok := schema["$ref"].(string); ok {
		name := strings.TrimPrefix(pointer, "#/components/schemas/")
		target, exists := spec.Components.Schemas[name]
		if !exists {
			return fmt.Errorf("%s unresolved ref %s", path, pointer)
		}
		return spec.responseShape(target, value, path)
	}
	if schema["writeOnly"] == true {
		return fmt.Errorf("%s exposed a writeOnly field", path)
	}
	var types []string
	switch kind := schema["type"].(type) {
	case string:
		types = []string{kind}
	case []any:
		for _, item := range kind {
			types = append(types, item.(string))
		}
	}
	match := len(types) == 0
	for _, kind := range types {
		switch kind {
		case "null":
			match = match || value == nil
		case "object":
			_, ok := value.(map[string]any)
			match = match || ok
		case "array":
			_, ok := value.([]any)
			match = match || ok
		case "boolean":
			_, ok := value.(bool)
			match = match || ok
		case "string":
			_, ok := value.(string)
			match = match || ok
		case "number", "integer":
			number, ok := value.(float64)
			match = match || (ok && (kind == "number" || math.Trunc(number) == number))
		}
	}
	if !match {
		return fmt.Errorf("%s type %T does not match %v", path, value, types)
	}
	if choices, ok := schema["enum"].([]any); ok {
		found := false
		for _, item := range choices {
			found = found || reflect.DeepEqual(item, value)
		}
		if !found {
			return fmt.Errorf("%s value outside enum", path)
		}
	}
	if constant, ok := schema["const"]; ok && !reflect.DeepEqual(constant, value) {
		return fmt.Errorf("%s value differs from const", path)
	}
	if text, ok := value.(string); ok && schema["format"] == "date-time" {
		if _, err := time.Parse(time.RFC3339Nano, text); err != nil {
			return fmt.Errorf("%s invalid date-time: %w", path, err)
		}
	}
	if fields, ok := value.(map[string]any); ok {
		properties, _ := schema["properties"].(map[string]any)
		if required, ok := schema["required"].([]any); ok {
			for _, name := range required {
				if _, exists := fields[name.(string)]; !exists {
					return fmt.Errorf("%s missing required field %s", path, name)
				}
			}
		}
		for name, field := range fields {
			child, exists := properties[name]
			if !exists {
				if schema["additionalProperties"] == false {
					return fmt.Errorf("%s unexpected field %s", path, name)
				}
				continue
			}
			if err := spec.responseShape(child.(map[string]any), field, path+"."+name); err != nil {
				return err
			}
		}
	}
	if items, ok := value.([]any); ok {
		if max, ok := schema["maxItems"].(float64); ok && len(items) > int(max) {
			return fmt.Errorf("%s exceeds maxItems", path)
		}
		for i, item := range items {
			if err := spec.responseShape(schema["items"].(map[string]any), item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func TestOpenAPIHTTPResponses(t *testing.T) {
	spec := readOpenAPI(t)
	st := initializedAuthStore(t)
	handler := testAPIHandler(t, st) // Engine workers are never started; provider is nil.
	session, csrf := loginCookies(t, handler)
	cookies := []*http.Cookie{session, csrf}
	headers := map[string]string{"X-CDT-CSRF": csrf.Value}
	seen := map[string]bool{}
	check := func(method, template string, response *httptest.ResponseRecorder, expected int) map[string]any {
		t.Helper()
		if response.Code != expected {
			t.Fatalf("%s %s status=%d, want=%d, body=%s", method, template, response.Code, expected, response.Body.String())
		}
		seen[method+" "+template] = true
		op := spec.Paths[template][strings.ToLower(method)]
		documented, ok := op.Responses[strconv.Itoa(response.Code)]
		if !ok {
			t.Fatalf("%s %s returned undocumented status %d", method, template, response.Code)
		}
		if expected == 304 {
			if response.Body.Len() != 0 || len(documented.Content) != 0 {
				t.Fatal("304 must have no body or content schema")
			}
			return nil
		}
		if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s %s is not JSON", method, template)
		}
		var value any
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if err := spec.responseShape(documented.Content["application/json"].Schema, value, template); err != nil {
			t.Fatal(err)
		}
		object := value.(map[string]any)
		if expected >= 400 {
			code := object["error"].(map[string]any)["code"].(string)
			found := false
			for _, documentedCode := range documented.Codes {
				found = found || code == documentedCode
			}
			if !found {
				t.Fatalf("%s %s undocumented error code %s", method, template, code)
			}
		}
		return object
	}
	request := func(method, template, path, body string, expected int) map[string]any {
		t.Helper()
		return check(method, template, doRequest(t, handler, method, path, body, cookies, headers), expected)
	}
	for _, path := range []string{"/healthz", "/readyz", "/api/v1/system/init-status", "/api/v1/system/info", "/api/v1/widget/summary", "/api/v1/admin/passkeys", "/api/v1/api-keys", "/api/v1/logs", "/api/v1/accounts/1/history"} {
		template := path
		if strings.HasSuffix(path, "/history") {
			template = "/api/v1/accounts/{id}/history"
		}
		request("GET", template, path, "", 200)
	}
	config := request("GET", "/api/v1/config", "/api/v1/config", "", 200)
	configBody, _ := json.Marshal(config)
	request("PUT", "/api/v1/config", "/api/v1/config", string(configBody), 200)
	request("PUT", "/api/v1/config", "/api/v1/config", `{"unknown":true}`, 400)
	request("PATCH", "/api/v1/accounts/{id}/settings", "/api/v1/accounts/1/settings", `{"keep_alive":"default","daily_report":null}`, 200)
	request("POST", "/api/v1/accounts/discover", "/api/v1/accounts/discover", `{"source_account_id":1,"access_key_id":"LTAItest","region_id":"cn-beijing"}`, 502)
	request("POST", "/api/v1/accounts/refresh", "/api/v1/accounts/refresh", "", 202)
	job := request("POST", "/api/v1/accounts/{id}/refresh", "/api/v1/accounts/1/refresh", "", 202)
	if job["id"] == "" || job["job_id"] != nil {
		t.Fatal("async response must use id, not job_id")
	}
	request("GET", "/api/v1/jobs/{id}", "/api/v1/jobs/"+job["id"].(string), "", 200)
	request("POST", "/api/v1/accounts/{id}/actions/{action}", "/api/v1/accounts/1/actions/start", "", 202)
	request("POST", "/api/v1/accounts/{id}/actions/{action}", "/api/v1/accounts/1/actions/restart", "", 400)
	request("POST", "/api/v1/accounts/{id}/refresh", "/api/v1/accounts/999/refresh", "", 500)
	request("POST", "/api/v1/notifications/daily-report", "/api/v1/notifications/daily-report", "", 202)
	// OAPI-OBS-2 characterization only, not a compatibility guarantee. An independently
	// authorized decoder-validation fix should update this assertion and the contract.
	request("POST", "/api/v1/notifications/daily-report", "/api/v1/notifications/daily-report", `{"account_id":`, 202)
	request("POST", "/api/v1/notifications/test/{channel}", "/api/v1/notifications/test/email", "", 202)
	request("DELETE", "/api/v1/logs", "/api/v1/logs?tab=action", "", 200)
	key := request("POST", "/api/v1/api-keys", "/api/v1/api-keys", `{"name":"contract-fixture","scopes":["widget:read","instance:control","cron:run"]}`, 201)
	keyHeader := map[string]string{"X-API-Key": key["token"].(string)}
	check("POST", "/api/v1/accounts/{id}/refresh", doRequest(t, handler, "POST", "/api/v1/accounts/1/refresh", "", nil, keyHeader), 202)
	check("GET", "/api/v1/config", doRequest(t, handler, "GET", "/api/v1/config", "", nil, keyHeader), 403)
	check("PUT", "/api/v1/config", doRequest(t, handler, "PUT", "/api/v1/config", string(configBody), cookies, nil), 403)
	check("GET", "/api/v1/status", doRequest(t, handler, "GET", "/api/v1/status", "", cookies, map[string]string{"X-API-Key": "invalid-fixture"}), 401)
	check("GET", "/monitor.php", doRequest(t, handler, "GET", "/monitor.php", "", cookies, nil), 401)
	check("GET", "/monitor.php", doRequest(t, handler, "GET", "/monitor.php", "", nil, keyHeader), 202)
	// The first Engine owns the lease; a separate Engine has a different owner.
	check("GET", "/monitor.php", doRequest(t, testAPIHandler(t, st), "GET", "/monitor.php", "", nil, keyHeader), 409)
	status := doRequest(t, handler, "GET", "/api/v1/status", "", cookies, nil)
	check("GET", "/api/v1/status", status, 200)
	check("GET", "/api/v1/status", doRequest(t, handler, "GET", "/api/v1/status", "", cookies, map[string]string{"If-None-Match": status.Header().Get("ETag")}), 304)
	keyID := key["key"].(map[string]any)["id"].(float64)
	request("DELETE", "/api/v1/api-keys/{id}", fmt.Sprintf("/api/v1/api-keys/%.0f", keyID), "", 200)
	request("POST", "/api/v1/admin/passkeys/register/begin", "/api/v1/admin/passkeys/register/begin", `{"name":"contract"}`, 200)
	request("POST", "/api/v1/admin/passkeys/register/complete", "/api/v1/admin/passkeys/register/complete?session_id=missing", `{}`, 400)
	request("POST", "/api/v1/auth/passkeys/begin", "/api/v1/auth/passkeys/begin", "", 404)
	if err := st.SavePasskey(t.Context(), "contract-fixture", webauthn.Credential{ID: []byte("contract-id"), PublicKey: []byte("fixture-not-cryptographic-key")}); err != nil {
		t.Fatal(err)
	}
	request("POST", "/api/v1/auth/passkeys/begin", "/api/v1/auth/passkeys/begin", "", 200)
	request("POST", "/api/v1/auth/passkeys/complete", "/api/v1/auth/passkeys/complete?session_id=missing", `{}`, 400)
	request("GET", "/api/v1/admin/passkeys", "/api/v1/admin/passkeys", "", 200)
	request("DELETE", "/api/v1/admin/passkeys/{id}", "/api/v1/admin/passkeys/1", "", 200)
	request("PUT", "/api/v1/admin/password", "/api/v1/admin/password", `{"current_password":"`+testAdminPassword+`","new_password":"Contract-Password-84!"}`, 200)
	request("POST", "/api/v1/auth/logout", "/api/v1/auth/logout", "", 200)
	check("POST", "/api/v1/auth/login", doRequest(t, handler, "POST", "/api/v1/auth/login", `{"password":"Contract-Password-84!"}`, nil, nil), 200)
	fresh, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	check("POST", "/api/v1/setup", doRequest(t, testAPIHandler(t, fresh), "POST", "/api/v1/setup", `{"admin_password":"Contract-Setup-42!"}`, nil, nil), 201)
	for path, methods := range spec.Paths {
		for method := range methods {
			if !seen[strings.ToUpper(method)+" "+path] {
				t.Errorf("no runtime response exercised for %s %s", method, path)
			}
		}
	}
	t.Logf("checked response schemas/errors for all %d operations with isolated SQLite and no running workers", len(seen))
}

// Fix the minute in the same key constructor used by both refresh handlers: this
// proves key release, rather than accidentally passing after a wall-clock rollover.
// No provider/worker is run; lifecycle transitions use the production store API.
func TestOpenAPIRefreshDedupeKeyLifetime(t *testing.T) {
	for _, terminal := range []string{"completed", "failed"} {
		t.Run(terminal, func(t *testing.T) {
			st := initializedAuthStore(t)
			ctx := t.Context()
			key := engine.JobUniqueKey(engine.JobRefreshAccount, 1, "202610021430")
			enqueue := func() domain.Job {
				t.Helper()
				job, err := st.EnqueueJob(ctx, engine.JobRefreshAccount, 1, `{}`, key, 1)
				if err != nil {
					t.Fatal(err)
				}
				return job
			}
			first := enqueue()
			if duplicate := enqueue(); duplicate.ID != first.ID || duplicate.Status != "queued" {
				t.Fatalf("queued job should retain the same minute key: %#v", duplicate)
			}
			claimed, err := st.ClaimJob(ctx)
			if err != nil || claimed.ID != first.ID || claimed.Status != "running" {
				t.Fatalf("claim=%#v err=%v", claimed, err)
			}
			if duplicate := enqueue(); duplicate.ID != first.ID || duplicate.Status != "running" {
				t.Fatalf("running job should retain the same minute key: %#v", duplicate)
			}
			if terminal == "completed" {
				err = st.CompleteJob(ctx, claimed.ID, "fixture complete")
			} else {
				// maxAttempts=1: this real first claim exhausts the retry budget.
				err = st.FailJob(ctx, claimed, errors.New("fixture terminal failure"))
			}
			if err != nil {
				t.Fatal(err)
			}
			old, err := st.GetJob(ctx, first.ID)
			if err != nil || old.Status != terminal {
				t.Fatalf("old job=%#v err=%v", old, err)
			}
			if next := enqueue(); next.ID == first.ID || next.Status != "queued" {
				t.Fatalf("%s refresh must allow a new job with the exact same minute key: %#v", terminal, next)
			}
		})
	}
	t.Run("retry-retains-key", func(t *testing.T) {
		st := initializedAuthStore(t)
		ctx := t.Context()
		key := engine.JobUniqueKey(engine.JobRefreshAccount, 1, "202610021430")
		first, err := st.EnqueueJob(ctx, engine.JobRefreshAccount, 1, `{}`, key, 2)
		if err != nil {
			t.Fatal(err)
		}
		claimed, err := st.ClaimJob(ctx)
		if err != nil || claimed.ID != first.ID || claimed.Attempts >= claimed.MaxAttempts {
			t.Fatalf("claim=%#v err=%v", claimed, err)
		}
		if err = st.FailJob(ctx, claimed, errors.New("fixture retryable failure")); err != nil {
			t.Fatal(err)
		}
		duplicate, err := st.EnqueueJob(ctx, engine.JobRefreshAccount, 1, `{}`, key, 2)
		if err != nil || duplicate.ID != first.ID || duplicate.Status != "queued" || duplicate.Attempts != 1 {
			t.Fatalf("retryable failure must keep the minute key on the requeued job: %#v err=%v", duplicate, err)
		}
	})
}

func TestOpenAPIResponseGuardRejectsDrift(t *testing.T) {
	spec := readOpenAPI(t)
	for _, test := range []struct {
		name, schema, body string
	}{
		{"missing-id", "Job", `{"job_id":"old-contract"}`},
		{"wrong-type", "Success", `{"success":"true"}`},
		{"wrong-value", "Success", `{"success":false}`},
		{"extra-field", "Success", `{"success":true,"unexpected":true}`},
		{"secret-leak", "EmailConfig", `{"enabled":false,"to":"","host":"","port":465,"username":"","security":"ssl","password_configured":true,"password":"fixture"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			var value any
			if err := json.Unmarshal([]byte(test.body), &value); err != nil {
				t.Fatal(err)
			}
			if err := spec.responseShape(spec.Components.Schemas[test.schema], value, test.schema); err == nil {
				t.Fatal("response guard accepted schema drift")
			}
		})
	}
}
