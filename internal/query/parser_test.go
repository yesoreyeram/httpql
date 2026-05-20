package query

import (
	"encoding/json"
	"net/url"
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/body"
)

// ─── helper ───────────────────────────────────────────────────────────────────

func mustParse(t *testing.T, src string) *ParsedQuery {
	t.Helper()
	pq, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): unexpected error: %v", src, err)
	}
	return pq
}

func errParse(t *testing.T, src string) error {
	t.Helper()
	_, err := Parse(src)
	if err == nil {
		t.Fatalf("Parse(%q): expected error, got nil", src)
	}
	return err
}

// ─── simple request tests ─────────────────────────────────────────────────────

func TestSimpleGET(t *testing.T) {
	pq := mustParse(t, "GET https://api.example.com/users")

	if len(pq.Requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(pq.Requests))
	}
	req := pq.Requests[0].Request
	if req.Method != "GET" {
		t.Errorf("method: want GET, got %q", req.Method)
	}
	if req.URL != "https://api.example.com/users" {
		t.Errorf("URL: want https://api.example.com/users, got %q", req.URL)
	}
	if pq.Requests[0].Name != "" {
		t.Errorf("Name: want empty, got %q", pq.Requests[0].Name)
	}
	if pq.Plan.WithBlocks != 1 {
		t.Errorf("WithBlocks: want 1, got %d", pq.Plan.WithBlocks)
	}
	if len(pq.Plan.URLs) != 1 || pq.Plan.URLs[0] != "https://api.example.com/users" {
		t.Errorf("Plan.URLs: want [https://api.example.com/users], got %v", pq.Plan.URLs)
	}
}

func TestSimpleGETCaseInsensitiveMethod(t *testing.T) {
	pq := mustParse(t, "get https://api.example.com/x")
	if pq.Requests[0].Request.Method != "GET" {
		t.Errorf("expected GET, got %q", pq.Requests[0].Request.Method)
	}
}

func TestSimplePOST(t *testing.T) {
	pq := mustParse(t, "POST https://api.example.com/items")
	req := pq.Requests[0].Request
	if req.Method != "POST" {
		t.Errorf("method: want POST, got %q", req.Method)
	}
}

func TestAllMethods(t *testing.T) {
	methods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
	for _, m := range methods {
		pq := mustParse(t, m+" https://example.com/")
		if pq.Requests[0].Request.Method != m {
			t.Errorf("method: want %s, got %s", m, pq.Requests[0].Request.Method)
		}
	}
}

// ─── HEADERS tests ────────────────────────────────────────────────────────────

func TestGETWithHeaders(t *testing.T) {
	src := `GET https://api.example.com/users
HEADERS {"Accept": "application/json", "X-Token": "abc"}`
	pq := mustParse(t, src)
	req := pq.Requests[0].Request
	if req.Headers["Accept"] != "application/json" {
		t.Errorf("Accept: want application/json, got %q", req.Headers["Accept"])
	}
	if req.Headers["X-Token"] != "abc" {
		t.Errorf("X-Token: want abc, got %q", req.Headers["X-Token"])
	}
}

func TestGETWithMultilineHeaders(t *testing.T) {
	src := `GET https://api.example.com/users
HEADERS {
  "Accept": "application/json",
  "Authorization": "Bearer token123"
}`
	pq := mustParse(t, src)
	req := pq.Requests[0].Request
	if req.Headers["Authorization"] != "Bearer token123" {
		t.Errorf("Authorization: want Bearer token123, got %q", req.Headers["Authorization"])
	}
}

// ─── BODY tests ───────────────────────────────────────────────────────────────

func TestBODYJSON(t *testing.T) {
	src := `POST https://api.example.com/items
BODY JSON {"name":"widget","qty":5}`
	pq := mustParse(t, src)
	req := pq.Requests[0].Request
	if req.BodyProvider == nil {
		t.Fatal("BodyProvider is nil")
	}
	data, ct, err := req.BodyProvider.Build()
	if err != nil {
		t.Fatalf("Build(): %v", err)
	}
	if ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if m["name"] != "widget" {
		t.Errorf("name: want widget, got %v", m["name"])
	}
}

func TestBODYJSONArray(t *testing.T) {
	src := `POST https://api.example.com/batch
BODY JSON [{"id":1},{"id":2}]`
	pq := mustParse(t, src)
	data, ct, err := pq.Requests[0].Request.BodyProvider.Build()
	if err != nil {
		t.Fatal(err)
	}
	if ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
	var arr []map[string]any
	if err := json.Unmarshal(data, &arr); err != nil {
		t.Fatalf("unmarshal body array: %v", err)
	}
	if len(arr) != 2 {
		t.Errorf("array len: want 2, got %d", len(arr))
	}
}

func TestBODYFORM(t *testing.T) {
	src := `POST https://example.com/login
BODY FORM username=alice&password=s3cr3t`
	pq := mustParse(t, src)
	req := pq.Requests[0].Request
	if req.BodyProvider == nil {
		t.Fatal("BodyProvider is nil")
	}
	fp, ok := req.BodyProvider.(body.Form)
	if !ok {
		t.Fatalf("BodyProvider type: want body.Form, got %T", req.BodyProvider)
	}
	want := url.Values{"username": {"alice"}, "password": {"s3cr3t"}}
	if fp.Values.Encode() != want.Encode() {
		t.Errorf("form values: want %v, got %v", want, fp.Values)
	}
}

func TestBODYTEXT(t *testing.T) {
	src := `POST https://example.com/log
BODY TEXT event=login user=alice`
	pq := mustParse(t, src)
	data, ct, err := pq.Requests[0].Request.BodyProvider.Build()
	if err != nil {
		t.Fatal(err)
	}
	if ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type: want text/plain; charset=utf-8, got %q", ct)
	}
	if string(data) != "event=login user=alice" {
		t.Errorf("body: want %q, got %q", "event=login user=alice", string(data))
	}
}

func TestBODYRAW(t *testing.T) {
	src := `POST https://example.com/binary
BODY RAW hello-world`
	pq := mustParse(t, src)
	rawP, ok := pq.Requests[0].Request.BodyProvider.(body.Raw)
	if !ok {
		t.Fatalf("BodyProvider type: want body.Raw, got %T", pq.Requests[0].Request.BodyProvider)
	}
	if string(rawP.Data) != "hello-world" {
		t.Errorf("data: want hello-world, got %q", string(rawP.Data))
	}
}

func TestBODYGRAPHQL(t *testing.T) {
	src := `POST https://api.example.com/graphql
BODY GRAPHQL {"query":"query GetUser($id: ID!) { user(id: $id) { name } }","variables":{"id":"42"}}`
	pq := mustParse(t, src)
	gp, ok := pq.Requests[0].Request.BodyProvider.(body.GraphQL)
	if !ok {
		t.Fatalf("BodyProvider type: want body.GraphQL, got %T", pq.Requests[0].Request.BodyProvider)
	}
	if gp.Query == "" {
		t.Error("GraphQL.Query is empty")
	}
	if gp.Variables["id"] != "42" {
		t.Errorf("variables.id: want 42, got %v", gp.Variables["id"])
	}
	_, ct, err := pq.Requests[0].Request.BodyProvider.Build()
	if err != nil {
		t.Fatal(err)
	}
	if ct != "application/json" {
		t.Errorf("Content-Type: want application/json, got %q", ct)
	}
}

// ─── WITH clause tests ────────────────────────────────────────────────────────

func TestWITHClause(t *testing.T) {
	src := `WITH
  users  AS (GET https://api.example.com/users),
  orders AS (GET https://api.example.com/orders)`
	pq := mustParse(t, src)

	if len(pq.Requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(pq.Requests))
	}
	if pq.Requests[0].Name != "users" {
		t.Errorf("requests[0].Name: want users, got %q", pq.Requests[0].Name)
	}
	if pq.Requests[1].Name != "orders" {
		t.Errorf("requests[1].Name: want orders, got %q", pq.Requests[1].Name)
	}
	if pq.Plan.WithBlocks != 2 {
		t.Errorf("WithBlocks: want 2, got %d", pq.Plan.WithBlocks)
	}
	if len(pq.Plan.URLs) != 2 {
		t.Errorf("Plan.URLs len: want 2, got %d", len(pq.Plan.URLs))
	}
}

func TestWITHClauseWithHeaders(t *testing.T) {
	src := `WITH
  users AS (
    GET https://api.example.com/users
    HEADERS {"Accept": "application/json"}
  )`
	pq := mustParse(t, src)
	if len(pq.Requests) != 1 {
		t.Fatalf("expected 1 request, got %d", len(pq.Requests))
	}
	if pq.Requests[0].Request.Headers["Accept"] != "application/json" {
		t.Errorf("Accept: want application/json, got %q", pq.Requests[0].Request.Headers["Accept"])
	}
}

func TestWITHClauseNoParen(t *testing.T) {
	// Named requests don't require parentheses when there's only one.
	src := `WITH single AS GET https://api.example.com/x`
	pq := mustParse(t, src)
	if len(pq.Requests) != 1 || pq.Requests[0].Name != "single" {
		t.Fatalf("unexpected parse result: %+v", pq.Requests)
	}
}

// ─── hint tests ───────────────────────────────────────────────────────────────

func TestHintCONCURRENCY(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nCONCURRENCY 4")
	if pq.Plan.ConcurrencyHint != 4 {
		t.Errorf("ConcurrencyHint: want 4, got %d", pq.Plan.ConcurrencyHint)
	}
}

func TestHintQUERY_TIMEOUT(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nQUERY_TIMEOUT 30")
	if pq.Plan.QueryTimeoutHint != 30 {
		t.Errorf("QueryTimeoutHint: want 30, got %d", pq.Plan.QueryTimeoutHint)
	}
}

func TestHintREQUEST_CACHE(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nREQUEST_CACHE 300")
	if pq.Plan.RequestCacheTTLHint != 300 {
		t.Errorf("RequestCacheTTLHint: want 300, got %d", pq.Plan.RequestCacheTTLHint)
	}
	// Verify TTL was propagated to the request.
	if pq.Requests[0].Request.CacheTTL != 300*time.Second {
		t.Errorf("Request.CacheTTL: want 300s, got %v", pq.Requests[0].Request.CacheTTL)
	}
}

func TestHintCACHE(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nCACHE 60")
	if pq.Plan.ResponseCacheTTLHint != 60 {
		t.Errorf("ResponseCacheTTLHint: want 60, got %d", pq.Plan.ResponseCacheTTLHint)
	}
}

func TestHintRETRY(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nRETRY 3")
	if pq.Plan.RetryHint != 3 {
		t.Errorf("RetryHint: want 3, got %d", pq.Plan.RetryHint)
	}
}

func TestHintREDIRECTS(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nREDIRECTS FOLLOW MAX 5")
	if pq.Plan.RedirectMaxHint != 5 {
		t.Errorf("RedirectMaxHint: want 5, got %d", pq.Plan.RedirectMaxHint)
	}
}

func TestHintSTOP_WHEN_TOTAL_ITEMS(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nSTOP_WHEN TOTAL_ITEMS >= 1000")
	if pq.Plan.MaxRowsHint != 1000 {
		t.Errorf("MaxRowsHint: want 1000, got %d", pq.Plan.MaxRowsHint)
	}
}

func TestHintSTOP_WHEN_PAGE_COUNT(t *testing.T) {
	pq := mustParse(t, "GET https://example.com/x\nSTOP_WHEN PAGE_COUNT >= 50")
	if pq.Plan.MaxPagesHint != 50 {
		t.Errorf("MaxPagesHint: want 50, got %d", pq.Plan.MaxPagesHint)
	}
}

func TestAllHintsInOneQuery(t *testing.T) {
	src := `GET https://example.com/data
CONCURRENCY 3
QUERY_TIMEOUT 30
REQUEST_CACHE 300
CACHE 60
RETRY 2
REDIRECTS FOLLOW MAX 5
STOP_WHEN TOTAL_ITEMS >= 1000
STOP_WHEN PAGE_COUNT >= 50`

	pq := mustParse(t, src)
	if pq.Plan.ConcurrencyHint != 3 {
		t.Errorf("ConcurrencyHint: want 3, got %d", pq.Plan.ConcurrencyHint)
	}
	if pq.Plan.QueryTimeoutHint != 30 {
		t.Errorf("QueryTimeoutHint: want 30, got %d", pq.Plan.QueryTimeoutHint)
	}
	if pq.Plan.RequestCacheTTLHint != 300 {
		t.Errorf("RequestCacheTTLHint: want 300, got %d", pq.Plan.RequestCacheTTLHint)
	}
	if pq.Plan.ResponseCacheTTLHint != 60 {
		t.Errorf("ResponseCacheTTLHint: want 60, got %d", pq.Plan.ResponseCacheTTLHint)
	}
	if pq.Plan.RetryHint != 2 {
		t.Errorf("RetryHint: want 2, got %d", pq.Plan.RetryHint)
	}
	if pq.Plan.RedirectMaxHint != 5 {
		t.Errorf("RedirectMaxHint: want 5, got %d", pq.Plan.RedirectMaxHint)
	}
	if pq.Plan.MaxRowsHint != 1000 {
		t.Errorf("MaxRowsHint: want 1000, got %d", pq.Plan.MaxRowsHint)
	}
	if pq.Plan.MaxPagesHint != 50 {
		t.Errorf("MaxPagesHint: want 50, got %d", pq.Plan.MaxPagesHint)
	}
}

// ─── comment tests ────────────────────────────────────────────────────────────

func TestComments(t *testing.T) {
	src := `-- Fetch users
GET https://api.example.com/users  -- inline comment
-- Request cache
CACHE 60`
	pq := mustParse(t, src)
	if pq.Requests[0].Request.URL != "https://api.example.com/users" {
		t.Errorf("URL: want https://api.example.com/users, got %q", pq.Requests[0].Request.URL)
	}
	if pq.Plan.ResponseCacheTTLHint != 60 {
		t.Errorf("CACHE: want 60, got %d", pq.Plan.ResponseCacheTTLHint)
	}
}

// ─── error tests ──────────────────────────────────────────────────────────────

func TestErrorEmptyQuery(t *testing.T) {
	errParse(t, "")
	errParse(t, "   ")
	errParse(t, "-- just a comment")
}

func TestErrorUnknownMethod(t *testing.T) {
	errParse(t, "FETCH https://example.com/x")
}

func TestErrorMissingURL(t *testing.T) {
	errParse(t, "GET")
}

func TestErrorInvalidURL(t *testing.T) {
	errParse(t, "GET not-a-url")
}

func TestErrorInvalidHeadersJSON(t *testing.T) {
	errParse(t, `GET https://example.com/x
HEADERS {bad json}`)
}

func TestErrorBODYJSONNotJSON(t *testing.T) {
	errParse(t, `POST https://example.com/x
BODY JSON not-json`)
}

func TestErrorBODYUnknownType(t *testing.T) {
	errParse(t, `POST https://example.com/x
BODY YAML key: value`)
}

func TestErrorBODYGRAPHQLMissingQuery(t *testing.T) {
	errParse(t, `POST https://example.com/graphql
BODY GRAPHQL {"variables":{}}`)
}

func TestErrorWITHMissingAS(t *testing.T) {
	errParse(t, `WITH users GET https://example.com/users`)
}

func TestErrorSTOP_WHENUnknownTarget(t *testing.T) {
	errParse(t, `GET https://example.com/x
STOP_WHEN ROW_COUNT >= 100`)
}

func TestErrorTrailingTokens(t *testing.T) {
	errParse(t, "GET https://example.com/x EXTRA")
}

// ─── scanner unit tests ───────────────────────────────────────────────────────

func TestScannerGTE(t *testing.T) {
	s := newScanner(">= 100")
	tok := s.next()
	if tok.kind != tokGTE {
		t.Fatalf("kind: want tokGTE, got %d", tok.kind)
	}
	tok = s.next()
	if tok.kind != tokInt || tok.val != "100" {
		t.Fatalf("int token: want 100, got %q (kind %d)", tok.val, tok.kind)
	}
}

func TestScannerJSON(t *testing.T) {
	s := newScanner(`{"key":"value","nested":{"a":1}}`)
	tok := s.next()
	if tok.kind != tokJSON {
		t.Fatalf("kind: want tokJSON, got %d", tok.kind)
	}
	if !json.Valid([]byte(tok.val)) {
		t.Errorf("scanned JSON is not valid: %q", tok.val)
	}
}

func TestScannerURL(t *testing.T) {
	s := newScanner("https://api.example.com/users?q=1")
	tok := s.next()
	if tok.kind != tokURL {
		t.Fatalf("kind: want tokURL, got %d", tok.kind)
	}
	if tok.val != "https://api.example.com/users?q=1" {
		t.Errorf("URL: want https://api.example.com/users?q=1, got %q", tok.val)
	}
}

func TestScannerReadLine(t *testing.T) {
	s := newScanner("  hello world\nnext")
	line := s.readLine()
	if line != "hello world" {
		t.Errorf("readLine: want %q, got %q", "hello world", line)
	}
	// next token should be on the next line
	tok := s.next()
	if tok.val != "next" {
		t.Errorf("after readLine: want next, got %q", tok.val)
	}
}

func TestScannerComment(t *testing.T) {
	s := newScanner("-- comment\nGET")
	tok := s.next()
	if tok.kind != tokWord || tok.val != "GET" {
		t.Fatalf("want GET word token, got kind=%d val=%q", tok.kind, tok.val)
	}
}

// ─── secret / env-ref / chain ref counting ────────────────────────────────────

func TestSecretRefsInURL(t *testing.T) {
pq := mustParse(t, "GET https://api.example.com/data?key=${secret:MY_KEY}")
if pq.Plan.SecretRefs != 1 {
t.Errorf("SecretRefs: want 1, got %d", pq.Plan.SecretRefs)
}
}

func TestSecretRefsInHeader(t *testing.T) {
pq := mustParse(t, `GET https://api.example.com/data
HEADERS {"Authorization": "Bearer ${secret:API_TOKEN}"}`)
if pq.Plan.SecretRefs != 1 {
t.Errorf("SecretRefs: want 1, got %d", pq.Plan.SecretRefs)
}
}

func TestMultipleSecretRefsCountedCorrectly(t *testing.T) {
pq := mustParse(t, `GET https://api.example.com/data
HEADERS {"Authorization": "Bearer ${secret:TOKEN}", "X-Secret": "${secret:OTHER}"}`)
if pq.Plan.SecretRefs != 2 {
t.Errorf("SecretRefs: want 2, got %d", pq.Plan.SecretRefs)
}
}

func TestSecretRefsInTextBody(t *testing.T) {
pq := mustParse(t, "POST https://api.example.com/\nBODY TEXT user=${secret:USER}&pass=${secret:PASS}")
if pq.Plan.SecretRefs != 2 {
t.Errorf("SecretRefs: want 2, got %d", pq.Plan.SecretRefs)
}
}

func TestEnvRefRejectedInURL(t *testing.T) {
err := errParse(t, "GET https://api.example.com/data?key=${env:SOME_VAR}")
if err == nil {
t.Fatal("expected error for ${env:...} in URL")
}
}

func TestEnvRefRejectedInHeader(t *testing.T) {
err := errParse(t, `GET https://api.example.com/data
HEADERS {"Authorization": "${env:TOKEN}"}`)
if err == nil {
t.Fatal("expected error for ${env:...} in header")
}
}

func TestEnvRefRejectedInBody(t *testing.T) {
err := errParse(t, "POST https://api.example.com/\nBODY TEXT ${env:VAR}")
if err == nil {
t.Fatal("expected error for ${env:...} in body")
}
}

func TestResponseRefCountedAsPlanDepth(t *testing.T) {
pq := mustParse(t, `WITH
  auth AS (POST https://auth.example.com/token
    BODY FORM grant_type=client_credentials
  ),
  api  AS (GET  https://api.example.com/users
    HEADERS {"Authorization": "Bearer ${response:auth.body.access_token}"})`)
// The ${response:...} ref should increment PlanDepth.
if pq.Plan.PlanDepth != 1 {
t.Errorf("PlanDepth: want 1, got %d", pq.Plan.PlanDepth)
}
}

func TestNoSecretRefsWhenNonePlaceholders(t *testing.T) {
pq := mustParse(t, "GET https://api.example.com/users")
if pq.Plan.SecretRefs != 0 {
t.Errorf("SecretRefs: want 0, got %d", pq.Plan.SecretRefs)
}
if pq.Plan.PlanDepth != 0 {
t.Errorf("PlanDepth: want 0, got %d", pq.Plan.PlanDepth)
}
}
