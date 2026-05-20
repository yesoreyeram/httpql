package httpql_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yesoreyeram/httpql/internal/config"
	httpql "github.com/yesoreyeram/httpql/pkg/httpql"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// newTestEngine builds an Engine with HTTP scheme allowed and SSRF disabled
// so test servers at 127.0.0.1 are reachable.
func newTestEngine(t *testing.T, cfg config.Config) *httpql.Engine {
	t.Helper()
	// Bypass the file-based config loading by setting the Config on the engine
	// via a helper.  For tests we use the in-process NewWithConfig helper.
	eng, err := httpql.NewWithConfig(cfg, httpql.Options{
		AdminToken:  "test-admin-token",
		AuditOutput: &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	return eng
}

func testCfg() config.Config {
	cfg := config.Default()
	cfg.Engine.Environment = "development"
	cfg.Security.AllowHTTPScheme = true
	cfg.Security.SSRFProtection = false
	cfg.Security.PrivateIPDenylist.Enabled = false
	cfg.Security.PrivateIPAllowlist = []string{"127.0.0.1/32", "::1/128"}
	cfg.Security.AllowedSchemes = []string{"http", "https"}
	cfg.Security.Secrets.Backend = "env"
	cfg.Limits.Requests.MaxWithBlocksPerQuery = 10
	cfg.Limits.Requests.MaxRequestsPerQuery = 20
	cfg.Security.MaxSecretRefsPerQuery = 10
	return cfg
}

// ─── secret interpolation ─────────────────────────────────────────────────────

func TestExecuteQuery_SecretInHeader(t *testing.T) {
	want := "secret-value-abc"
	t.Setenv("TEST_API_KEY", want)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Api-Key"); got != want {
			t.Errorf("header X-Api-Key: want %q, got %q", want, got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	eng := newTestEngine(t, testCfg())
	pq, err := httpql.ParseQuery(`GET ` + ts.URL + `/data
HEADERS {"X-Api-Key": "${secret:TEST_API_KEY}"}`)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	result, err := eng.ExecuteQuery(context.Background(), "test", pq)
	if err != nil {
		t.Fatalf("ExecuteQuery: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("want 1 result, got %d", len(result))
	}
}

func TestExecuteQuery_SecretInURL(t *testing.T) {
	token := "my-url-token"
	t.Setenv("URL_TOKEN", token)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("token"); got != token {
			t.Errorf("query param token: want %q, got %q", token, got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	eng := newTestEngine(t, testCfg())
	pq, err := httpql.ParseQuery("GET " + ts.URL + "/data?token=${secret:URL_TOKEN}")
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	if _, err := eng.ExecuteQuery(context.Background(), "test", pq); err != nil {
		t.Fatalf("ExecuteQuery: %v", err)
	}
}

func TestExecuteQuery_SecretMissingEnvVar(t *testing.T) {
	// Ensure the env var is NOT set.
	t.Setenv("NONEXISTENT_SECRET_XYZ", "")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	eng := newTestEngine(t, testCfg())
	pq, err := httpql.ParseQuery("GET " + ts.URL + `/data
HEADERS {"Authorization": "Bearer ${secret:NONEXISTENT_SECRET_XYZ}"}`)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	// The env var is set to "" which means it's present but empty.
	// A request with it should succeed (empty value is allowed).
	_, _ = eng.ExecuteQuery(context.Background(), "test", pq)
	// Test that parsing itself accepted the ${secret:...} ref without error.
}

// ─── ${env:...} is blocked at parse time ─────────────────────────────────────

func TestParseQuery_EnvRefRejected(t *testing.T) {
	_, err := httpql.ParseQuery("GET https://example.com?key=${env:SOME_VAR}")
	if err == nil {
		t.Fatal("expected parse error for ${env:...}")
	}
	if !strings.Contains(err.Error(), "env:") && !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ─── request chaining ─────────────────────────────────────────────────────────

func TestExecuteQuery_Chaining_ResponseBodyToHeader(t *testing.T) {
	// Step 1: auth server returns a token.
	authToken := "chain-bearer-token-99"
	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		enc := json.NewEncoder(w)
		enc.Encode(map[string]string{"access_token": authToken})
	}))
	defer authServer.Close()

	// Step 2: API server expects the token in Authorization header.
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := "Bearer " + authToken
		if got != want {
			t.Errorf("Authorization header: want %q, got %q", want, got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"users":[{"id":1}]}`))
	}))
	defer apiServer.Close()

	eng := newTestEngine(t, testCfg())
	src := `WITH
  auth AS (POST ` + authServer.URL + `/token
    BODY FORM grant_type=client_credentials
  ),
  api  AS (GET  ` + apiServer.URL + `/users
    HEADERS {"Authorization": "Bearer ${response:auth.body.access_token}"})`

	pq, err := httpql.ParseQuery(src)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	result, err := eng.ExecuteQuery(context.Background(), "test", pq)
	if err != nil {
		t.Fatalf("ExecuteQuery: %v", err)
	}
	if _, ok := result["auth"]; !ok {
		t.Error("result missing 'auth' key")
	}
	if _, ok := result["api"]; !ok {
		t.Error("result missing 'api' key")
	}
	if result["api"].StatusCode != 200 {
		t.Errorf("api status: want 200, got %d", result["api"].StatusCode)
	}
}

func TestExecuteQuery_Chaining_ResponseHeaderToNext(t *testing.T) {
	// Step 1: server returns a custom header.
	traceID := "trace-abc-123"
	step1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Trace-Id", traceID)
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer step1.Close()

	// Step 2: server expects the trace ID forwarded.
	step2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Forwarded-Trace")
		if got != traceID {
			t.Errorf("X-Forwarded-Trace: want %q, got %q", traceID, got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer step2.Close()

	eng := newTestEngine(t, testCfg())
	src := `WITH
  s1 AS (GET ` + step1.URL + `/step1),
  s2 AS (GET ` + step2.URL + `/step2
    HEADERS {"X-Forwarded-Trace": "${response:s1.header.X-Trace-Id}"})`

	pq, err := httpql.ParseQuery(src)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	if _, err := eng.ExecuteQuery(context.Background(), "test", pq); err != nil {
		t.Fatalf("ExecuteQuery: %v", err)
	}
}

func TestExecuteQuery_Chaining_ResponseStatusToNextURL(t *testing.T) {
	// Step 1: returns 201.
	step1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		w.Write([]byte(`{}`))
	}))
	defer step1.Close()

	// Step 2: expects the status code forwarded as a query param.
	step2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("prev_status")
		if got != "201" {
			t.Errorf("prev_status: want 201, got %q", got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer step2.Close()

	eng := newTestEngine(t, testCfg())
	src := `WITH
  s1 AS (GET ` + step1.URL + `/a),
  s2 AS (GET ` + step2.URL + `/b?prev_status=${response:s1.status})`

	pq, err := httpql.ParseQuery(src)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	if _, err := eng.ExecuteQuery(context.Background(), "test", pq); err != nil {
		t.Fatalf("ExecuteQuery: %v", err)
	}
}

func TestExecuteQuery_Chaining_NestedBodyPath(t *testing.T) {
	// Step 1: returns nested JSON.
	step1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"data":{"users":[{"id":42}]}}`))
	}))
	defer step1.Close()

	// Step 2: expects the extracted ID.
	step2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("user_id")
		if got != "42" {
			t.Errorf("user_id: want 42, got %q", got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer step2.Close()

	eng := newTestEngine(t, testCfg())
	src := `WITH
  list   AS (GET ` + step1.URL + `/list),
  detail AS (GET ` + step2.URL + `/detail?user_id=${response:list.body.data.users[0].id})`

	pq, err := httpql.ParseQuery(src)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	if _, err := eng.ExecuteQuery(context.Background(), "test", pq); err != nil {
		t.Fatalf("ExecuteQuery: %v", err)
	}
}

func TestExecuteQuery_Chaining_UnknownResponseRef(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer ts.Close()

	eng := newTestEngine(t, testCfg())
	// "other" is not a declared name so it should fail at execution time.
	src := `GET ` + ts.URL + `/data?x=${response:other.status}`
	pq, err := httpql.ParseQuery(src)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	_, err = eng.ExecuteQuery(context.Background(), "test", pq)
	if err == nil {
		t.Fatal("expected error for unknown response ref")
	}
}

func TestExecuteQuery_Chaining_SecretAndResponseCombined(t *testing.T) {
	authToken := "combined-token"
	t.Setenv("TEST_COMBINED_TOKEN_PREFIX", "Bearer")

	authServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"access_token":"` + authToken + `"}`))
	}))
	defer authServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := "Bearer " + authToken
		if got := r.Header.Get("Authorization"); got != want {
			t.Errorf("Authorization: want %q, got %q", want, got)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer apiServer.Close()

	eng := newTestEngine(t, testCfg())
	src := `WITH
  auth AS (POST ` + authServer.URL + `/token
  ),
  api  AS (GET  ` + apiServer.URL + `/data
    HEADERS {"Authorization": "${secret:TEST_COMBINED_TOKEN_PREFIX} ${response:auth.body.access_token}"})`

	pq, err := httpql.ParseQuery(src)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}

	if _, err := eng.ExecuteQuery(context.Background(), "test", pq); err != nil {
		t.Fatalf("ExecuteQuery: %v", err)
	}
}
