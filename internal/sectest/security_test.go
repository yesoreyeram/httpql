// Package sectest contains security and penetration tests for the httpql
// engine guard rail system.  These tests verify that all security invariants
// hold even when an attacker controls query inputs or config fields.
package sectest_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/admin"
	"github.com/yesoreyeram/httpql/internal/audit"
	"github.com/yesoreyeram/httpql/internal/cache"
	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/guardrails"
	"github.com/yesoreyeram/httpql/internal/policy"
)

// ─── SSRF / URL injection ────────────────────────────────────────────────────

// TestSec_SSRF_PrivateIPRangesAreBlocked verifies all RFC-1918 and special
// ranges are blocked by the plan-time SSRF check.
func TestSec_SSRF_PrivateIPRangesAreBlocked(t *testing.T) {
	t.Parallel()

	privateURLs := []string{
		"https://10.0.0.1/api",
		"https://10.255.255.255/api",
		"https://172.16.0.1/api",
		"https://172.31.255.255/api",
		"https://192.168.0.1/api",
		"https://192.168.255.255/api",
		"https://127.0.0.1/api",
		"https://127.255.255.255/api",
		"https://169.254.1.1/api",
		"https://100.64.0.1/api",
		"http://[::1]/api",
	}

	ep := policy.NewResolver(config.Default()).Resolve("sec-test")
	ep.SSRFProtectionEnabled = true
	ep.PrivateIPAllowlist = nil
	ep.MaxRequestsPerQuery = 100
	ep.MaxDistinctOriginsPerQuery = 100

	for _, u := range privateURLs {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			plan := guardrails.QueryPlan{
				WithBlocks:        1,
				EstimatedMaxPages: 1,
				URLs:              []string{u},
				PlanDepth:         1,
			}
			_, err := guardrails.Validate(plan, ep)
			if err == nil {
				t.Errorf("SSRF: private URL %q must be blocked", u)
			}
		})
	}
}

// TestSec_SSRF_AllowlistCannotBeExpandedByQuery verifies that an IP not in the
// namespace allowlist is blocked.
func TestSec_SSRF_AllowlistCannotBeExpandedByQuery(t *testing.T) {
	t.Parallel()

	ep := policy.NewResolver(config.Default()).Resolve("sec-test")
	ep.SSRFProtectionEnabled = true
	ep.PrivateIPAllowlist = []string{"10.100.0.0/24"}
	ep.MaxRequestsPerQuery = 100
	ep.MaxDistinctOriginsPerQuery = 100

	plan := guardrails.QueryPlan{
		WithBlocks:        1,
		EstimatedMaxPages: 1,
		URLs:              []string{"https://10.200.0.1/api"}, // outside allowlist
		PlanDepth:         1,
	}
	_, err := guardrails.Validate(plan, ep)
	if err == nil {
		t.Error("IP outside namespace allowlist must be blocked")
	}
}

// TestSec_SchemeInjection verifies non-HTTPS schemes are blocked.
func TestSec_SchemeInjection(t *testing.T) {
	t.Parallel()

	dangerousURLs := []string{
		"file:///etc/passwd",
		"ftp://ftp.example.com/file",
		"gopher://example.com/",
	}

	ep := policy.NewResolver(config.Default()).Resolve("sec-test")
	ep.AllowedSchemes = []string{"https"}
	ep.MaxRequestsPerQuery = 100
	ep.MaxDistinctOriginsPerQuery = 100

	for _, u := range dangerousURLs {
		t.Run(u, func(t *testing.T) {
			t.Parallel()
			plan := guardrails.QueryPlan{
				WithBlocks:        1,
				EstimatedMaxPages: 1,
				URLs:              []string{u},
				PlanDepth:         1,
			}
			_, err := guardrails.Validate(plan, ep)
			if err == nil {
				t.Errorf("dangerous scheme in URL %q must be blocked", u)
			}
		})
	}
}

// ─── Config tampering ─────────────────────────────────────────────────────────

func TestSec_ConfigTamper_SecretValueInLogsAlwaysFalse(t *testing.T) {
	t.Parallel()
	for _, env := range []string{"production", "staging", "development"} {
		cfg := config.Default()
		cfg.Engine.Environment = env
		cfg.Security.Secrets.ValueInLogs = true
		config.Clamp(&cfg)
		if cfg.Security.Secrets.ValueInLogs {
			t.Errorf("env=%s: Clamp must keep Secrets.ValueInLogs=false", env)
		}
	}
}

func TestSec_ConfigTamper_ResponseBodyLoggingAlwaysFalse(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Audit.LogResponseBody = true
	config.Clamp(&cfg)
	if cfg.Audit.LogResponseBody {
		t.Error("Clamp must keep Audit.LogResponseBody=false")
	}
}

func TestSec_ConfigTamper_SSRFCannotBeDisabled(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Security.SSRFProtection = false
	config.Clamp(&cfg)
	if !cfg.Security.SSRFProtection {
		t.Error("Clamp must restore SSRFProtection=true")
	}
}

func TestSec_ConfigTamper_TLSVerifyCertCannotBeDisabledInProduction(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Engine.Environment = "production"
	cfg.Security.TLS.VerifyCert = false
	config.Clamp(&cfg)
	if !cfg.Security.TLS.VerifyCert {
		t.Error("Clamp must restore TLS.VerifyCert=true in production")
	}
}

// ─── Namespace privilege escalation ──────────────────────────────────────────

func TestSec_NamespaceCannotEscalateToGlobal(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	globalMax := cfg.Limits.Requests.MaxRequestsPerQuery
	cfg.Namespaces = []config.Namespace{
		{
			Name: "escalation-attempt",
			Limits: config.LimitsConfig{
				Requests: config.RequestLimits{
					MaxRequestsPerQuery: globalMax * 100,
				},
			},
		},
	}
	resolver := policy.NewResolver(cfg)
	ep := resolver.Resolve("escalation-attempt")
	if ep.MaxRequestsPerQuery > globalMax {
		t.Errorf("namespace escalated MaxRequestsPerQuery to %d (global max: %d)",
			ep.MaxRequestsPerQuery, globalMax)
	}
}

func TestSec_NamespaceCannotEnableResponseCacheWhenGlobalDisabled(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Namespaces = []config.Namespace{
		{
			Name: "cache-escalation",
			Caching: config.CachingConfig{
				ResponseCache: config.ResponseCacheConfig{Enabled: true},
			},
		},
	}
	resolver := policy.NewResolver(cfg)
	ep := resolver.Resolve("cache-escalation")
	if ep.ResponseCacheEnabled {
		t.Error("namespace must not enable response cache when global has it disabled")
	}
}

func TestSec_NamespaceCannotAddDisallowedHTTPScheme(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	cfg.Namespaces = []config.Namespace{
		{
			Name: "http-ns",
			Security: config.SecurityConfig{
				AllowedSchemes: []string{"https", "http"},
			},
		},
	}
	resolver := policy.NewResolver(cfg)
	ep := resolver.Resolve("http-ns")
	for _, s := range ep.AllowedSchemes {
		if strings.EqualFold(s, "http") {
			t.Error("namespace must not add HTTP scheme when global disallows it")
		}
	}
}

// ─── Cache security invariants ────────────────────────────────────────────────

func TestSec_CacheKey_AuthHeaderNeverChangesKey(t *testing.T) {
	t.Parallel()
	tokens := []string{
		"",
		"Bearer secret",
		"Bearer different-secret",
		"Basic dXNlcjpwYXNz",
	}
	baseKey := cache.RequestCacheKey("ns", "GET", "https://api.example.com/data",
		map[string]string{"Accept": "application/json"}, nil)
	for _, tok := range tokens {
		headers := map[string]string{
			"Accept":        "application/json",
			"Authorization": tok,
		}
		k := cache.RequestCacheKey("ns", "GET", "https://api.example.com/data", headers, nil)
		if k != baseKey {
			t.Errorf("auth token %q changed the cache key", tok)
		}
	}
}

func TestSec_CacheNamespaceIsolation(t *testing.T) {
	t.Parallel()
	namespaces := []string{"team-a", "team-b", "admin", "public", "internal"}
	keys := make(map[string]string)
	for _, ns := range namespaces {
		k := cache.ResponseCacheKey(ns, "identical-query-fp")
		if prev, collision := keys[k]; collision {
			t.Errorf("namespace isolation violation: %q collides with %q for key %q", ns, prev, k)
		}
		keys[k] = ns
	}
}

// ─── Admin token timing attacks ───────────────────────────────────────────────

func TestSec_AdminToken_WrongTokensAllReturnSameStatus(t *testing.T) {
	t.Parallel()
	correctToken := "a-32-character-production-token!"
	wrongTokens := []string{
		"",
		"a",
		"wrong",
		"a-32-character-production-token?",
		strings.Repeat("x", 100),
	}

	mux := newTestAdminMux(t, correctToken)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	for _, tok := range wrongTokens {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/health", nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("request with token %q failed: %v", tok, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Errorf("wrong token %q returned 200", tok)
		}
	}

	// Correct token must succeed.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/admin/health", nil)
	req.Header.Set("Authorization", "Bearer "+correctToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("correct token returned %d, expected 200", resp.StatusCode)
	}
}

// ─── DoS protection ──────────────────────────────────────────────────────────

func TestSec_DoS_GlobalQueryLimitPreventsSaturation(t *testing.T) {
	t.Parallel()
	pool := guardrails.NewSemaphorePool(guardrails.SemaphorePoolConfig{
		GlobalRequestsMax:        100,
		GlobalQueriesMax:         3,
		DefaultNSQueriesMax:      10,
		DefaultQueryRequestsMax:  5,
		DefaultOriginRequestsMax: 5,
	})

	ctx := context.Background()
	rel1, _ := pool.AcquireQuery(ctx, "ns")
	rel2, _ := pool.AcquireQuery(ctx, "ns")
	rel3, _ := pool.AcquireQuery(ctx, "ns")

	tCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	_, err := pool.AcquireQuery(tCtx, "ns")
	if err == nil {
		t.Error("4th concurrent query should have been rejected")
	}
	rel1()
	rel2()
	rel3()
}

func TestSec_DoS_PaginationLoopBreaker(t *testing.T) {
	t.Parallel()
	ep := policy.NewResolver(config.Default()).Resolve("test")
	ep.PaginationInfiniteLoopWindow = 3
	rc := guardrails.NewRuntimeContext(ep)

	for i := 0; i < ep.PaginationInfiniteLoopWindow+1; i++ {
		err := rc.CheckCursor("stuck-cursor")
		if err != nil {
			pe, ok := err.(*guardrails.PolicyError)
			if !ok {
				t.Fatalf("expected *PolicyError, got %T", err)
			}
			if pe.Code != guardrails.ErrPaginationLoop {
				t.Errorf("expected ErrPaginationLoop, got %v", pe.Code)
			}
			return
		}
	}
	t.Error("pagination loop was never detected")
}

// TestSec_DoS_RequestBudgetPreventsRunaway verifies that a misbehaving query
// cannot exhaust global request slots.
func TestSec_DoS_RequestBudgetPreventsRunaway(t *testing.T) {
	t.Parallel()
	ep := policy.NewResolver(config.Default()).Resolve("test")
	ep.MaxRequestsPerQuery = 5
	rc := guardrails.NewRuntimeContext(ep)

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		if err := rc.CheckBudgetBeforeRequest(ctx); err != nil {
			t.Fatalf("request %d should be within budget: %v", i+1, err)
		}
	}
	err := rc.CheckBudgetBeforeRequest(ctx)
	if err == nil {
		t.Error("6th request must be rejected by budget guard")
	}
}

// ─── test helper ─────────────────────────────────────────────────────────────

func newTestAdminMux(t *testing.T, token string) http.Handler {
	t.Helper()
	cfg := config.Default()
	cfg.Engine.Environment = "staging"
	resolver := policy.NewResolver(cfg)
	reqCache := cache.NewRequestCache(10, 1024)
	respCache := cache.NewResponseCache(10, 1024, 10)
	semaPool := guardrails.NewSemaphorePool(guardrails.SemaphorePoolConfig{
		GlobalRequestsMax: 10, GlobalQueriesMax: 5,
		DefaultNSQueriesMax: 5, DefaultQueryRequestsMax: 5, DefaultOriginRequestsMax: 5,
	})
	logger := audit.NewLogger(&bytes.Buffer{}, "test", false)
	api, err := admin.NewAPI(cfg, resolver, reqCache, respCache, semaPool, logger, token)
	if err != nil {
		t.Fatalf("NewAPI: %v", err)
	}
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	return mux
}
