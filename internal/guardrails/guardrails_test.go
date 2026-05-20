package guardrails_test

import (
	"context"
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/guardrails"
	"github.com/yesoreyeram/httpql/internal/policy"
)

// ─── helpers ─────────────────────────────────────────────────────────────────

func defaultPolicy() policy.EffectivePolicy {
	return policy.NewResolver(config.Default()).Resolve("test")
}

// ─── Planner ─────────────────────────────────────────────────────────────────

func TestValidate_AllowsValidPlan(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	plan := guardrails.QueryPlan{
		Namespace:         "test",
		WithBlocks:        2,
		EstimatedMaxPages: 1,
		URLs:              []string{"https://api.example.com/data"},
		SecretRefs:        0,
		PlanDepth:         3,
	}
	result, err := guardrails.Validate(plan, ep)
	if err != nil {
		t.Fatalf("expected valid plan to pass, got: %v", err)
	}
	if !result.Allowed {
		t.Error("expected Allowed=true")
	}
}

func TestValidate_RejectsExcessiveRequestCount(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy() // MaxRequestsPerQuery = 10

	// WithBlocks * pages * retries = 5 * 10 * 1 = 50 > 10
	plan := guardrails.QueryPlan{
		Namespace:         "test",
		WithBlocks:        5,
		EstimatedMaxPages: 10,
		URLs:              []string{"https://api.example.com/data"},
	}
	_, err := guardrails.Validate(plan, ep)
	if err == nil {
		t.Fatal("expected error for excessive request count")
	}
	pe, ok := err.(*guardrails.PolicyError)
	if !ok {
		t.Fatalf("expected *PolicyError, got %T", err)
	}
	if pe.Code != guardrails.ErrPolicyLimitExceeded {
		t.Errorf("expected ErrPolicyLimitExceeded, got %v", pe.Code)
	}
}

func TestValidate_RejectsSSRFPrivateIP(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.SSRFProtectionEnabled = true
	ep.PrivateIPAllowlist = nil

	plan := guardrails.QueryPlan{
		Namespace:         "test",
		WithBlocks:        1,
		EstimatedMaxPages: 1,
		URLs:              []string{"https://192.168.1.1/api"}, // private IP
		PlanDepth:         1,
	}
	_, err := guardrails.Validate(plan, ep)
	if err == nil {
		t.Fatal("expected SSRF block for private IP")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrSSRFBlocked {
		t.Errorf("expected ErrSSRFBlocked, got %v", pe.Code)
	}
}

func TestValidate_AllowsPrivateIPInAllowlist(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.SSRFProtectionEnabled = true
	ep.PrivateIPAllowlist = []string{"192.168.1.0/24"}
	ep.MaxRequestsPerQuery = 100

	plan := guardrails.QueryPlan{
		Namespace:         "test",
		WithBlocks:        1,
		EstimatedMaxPages: 1,
		URLs:              []string{"https://192.168.1.5/api"},
		PlanDepth:         1,
	}
	result, err := guardrails.Validate(plan, ep)
	if err != nil {
		t.Fatalf("expected allowlisted IP to pass SSRF check, got: %v", err)
	}
	if !result.Allowed {
		t.Error("expected Allowed=true for allowlisted IP")
	}
}

func TestValidate_BlocksLoopbackIP(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.SSRFProtectionEnabled = true
	ep.PrivateIPAllowlist = nil

	for _, ip := range []string{"127.0.0.1", "::1"} {
		plan := guardrails.QueryPlan{
			Namespace:         "test",
			WithBlocks:        1,
			EstimatedMaxPages: 1,
			URLs:              []string{"http://" + ip + "/api"},
			PlanDepth:         1,
		}
		_, err := guardrails.Validate(plan, ep)
		if err == nil {
			t.Errorf("expected SSRF block for loopback %s", ip)
		}
	}
}

func TestValidate_RejectsDisallowedScheme(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.AllowedSchemes = []string{"https"}

	plan := guardrails.QueryPlan{
		Namespace:         "test",
		WithBlocks:        1,
		EstimatedMaxPages: 1,
		URLs:              []string{"http://api.example.com/data"},
		PlanDepth:         1,
	}
	_, err := guardrails.Validate(plan, ep)
	if err == nil {
		t.Fatal("expected scheme rejection for http")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrSchemeNotAllowed {
		t.Errorf("expected ErrSchemeNotAllowed, got %v", pe.Code)
	}
}

func TestValidate_RejectsTooManySecretRefs(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy() // MaxSecretRefsPerQuery = 5

	plan := guardrails.QueryPlan{
		Namespace:         "test",
		WithBlocks:        1,
		EstimatedMaxPages: 1,
		URLs:              []string{"https://api.example.com/data"},
		SecretRefs:        10, // > 5
		PlanDepth:         1,
	}
	_, err := guardrails.Validate(plan, ep)
	if err == nil {
		t.Fatal("expected error for too many secret refs")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrPolicyLimitExceeded {
		t.Errorf("expected ErrPolicyLimitExceeded, got %v", pe.Code)
	}
}

func TestValidate_RejectsCyclicDependency(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.MaxRequestsPerQuery = 100

	plan := guardrails.QueryPlan{
		Namespace:           "test",
		WithBlocks:          1,
		EstimatedMaxPages:   1,
		URLs:                []string{"https://api.example.com/data"},
		HasCyclicDependency: true,
		PlanDepth:           1,
	}
	_, err := guardrails.Validate(plan, ep)
	if err == nil {
		t.Fatal("expected error for cyclic dependency")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrCyclicDependency {
		t.Errorf("expected ErrCyclicDependency, got %v", pe.Code)
	}
}

func TestValidate_RejectsTooDeepPlan(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy() // MaxQueryPlanDepth = 10

	plan := guardrails.QueryPlan{
		Namespace:         "test",
		WithBlocks:        1,
		EstimatedMaxPages: 1,
		URLs:              []string{"https://api.example.com/data"},
		PlanDepth:         20, // > 10
	}
	_, err := guardrails.Validate(plan, ep)
	if err == nil {
		t.Fatal("expected error for plan depth")
	}
}

// ─── RuntimeContext ───────────────────────────────────────────────────────────

func TestRuntimeContext_RequestBudget(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.MaxRequestsPerQuery = 3
	rc := guardrails.NewRuntimeContext(ep)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if err := rc.CheckBudgetBeforeRequest(ctx); err != nil {
			t.Fatalf("request %d should be within budget: %v", i+1, err)
		}
	}
	// 4th request should fail.
	if err := rc.CheckBudgetBeforeRequest(ctx); err == nil {
		t.Fatal("expected budget exceeded error on 4th request")
	} else {
		pe := err.(*guardrails.PolicyError)
		if pe.Code != guardrails.ErrRequestBudget {
			t.Errorf("expected ErrRequestBudget, got %v", pe.Code)
		}
	}
}

func TestRuntimeContext_WallClockTimeout(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.QueryWallClockTimeout = 1 * time.Millisecond
	rc := guardrails.NewRuntimeContext(ep)

	// Wait for deadline to pass.
	time.Sleep(5 * time.Millisecond)

	err := rc.CheckBudgetBeforeRequest(context.Background())
	if err == nil {
		t.Fatal("expected timeout error after deadline")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrQueryTimeout {
		t.Errorf("expected ErrQueryTimeout, got %v", pe.Code)
	}
}

func TestRuntimeContext_ContextCancelled(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	rc := guardrails.NewRuntimeContext(ep)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := rc.CheckBudgetBeforeRequest(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestRuntimeContext_BodyTooLarge(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	rc := guardrails.NewRuntimeContext(ep)

	err := rc.AddResponseBytes(1, 0) // perResponseMax = 0 → immediately over
	if err == nil {
		t.Fatal("expected body too large error")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrBodyTooLarge {
		t.Errorf("expected ErrBodyTooLarge, got %v", pe.Code)
	}
}

func TestRuntimeContext_BandwidthLimitPerQuery(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.MaxTotalBytesPerQuery = 100
	rc := guardrails.NewRuntimeContext(ep)

	// perResponseMax is generous; per-query total should trip first.
	err := rc.AddResponseBytes(101, 1024*1024)
	if err == nil {
		t.Fatal("expected bandwidth limit exceeded")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrBandwidthLimit {
		t.Errorf("expected ErrBandwidthLimit, got %v", pe.Code)
	}
}

func TestRuntimeContext_PaginationPageLimit(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.MaxPagesPerRequest = 3
	ep.MaxRowsPerQuery = 100_000
	rc := guardrails.NewRuntimeContext(ep)

	for i := 0; i < 3; i++ {
		if err := rc.AddPage(10); err != nil {
			t.Fatalf("page %d should be within limit: %v", i+1, err)
		}
	}
	err := rc.AddPage(10)
	if err == nil {
		t.Fatal("expected rows truncated error on 4th page")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrRowsTruncated {
		t.Errorf("expected ErrRowsTruncated, got %v", pe.Code)
	}
	if !pe.IsSoftLimit() {
		t.Error("pagination limit should be a soft limit")
	}
}

func TestRuntimeContext_PaginationRowLimit(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.MaxPagesPerRequest = 1000
	ep.MaxRowsPerQuery = 25
	rc := guardrails.NewRuntimeContext(ep)

	// 2 pages of 10 rows = 20 rows, within limit.
	for i := 0; i < 2; i++ {
		if err := rc.AddPage(10); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	// 3rd page of 10 rows = 30 total > 25.
	err := rc.AddPage(10)
	if err == nil {
		t.Fatal("expected row limit exceeded")
	}
}

func TestRuntimeContext_PaginationInfiniteLoopDetection(t *testing.T) {
	t.Parallel()
	ep := defaultPolicy()
	ep.PaginationInfiniteLoopWindow = 3
	rc := guardrails.NewRuntimeContext(ep)

	cursors := []string{"c1", "c2", "c3"}
	for _, c := range cursors {
		if err := rc.CheckCursor(c); err != nil {
			t.Fatalf("cursor %q should not trigger loop: %v", c, err)
		}
	}

	// Repeat a cursor — should trigger loop detection.
	err := rc.CheckCursor("c2")
	if err == nil {
		t.Fatal("expected infinite loop detection for repeated cursor")
	}
	pe := err.(*guardrails.PolicyError)
	if pe.Code != guardrails.ErrPaginationLoop {
		t.Errorf("expected ErrPaginationLoop, got %v", pe.Code)
	}
}

// ─── Semaphore ────────────────────────────────────────────────────────────────

func TestSemaphorePool_AcquireReleaseQuery(t *testing.T) {
	t.Parallel()
	pool := guardrails.NewSemaphorePool(guardrails.SemaphorePoolConfig{
		GlobalRequestsMax:        100,
		GlobalQueriesMax:         5,
		DefaultNSQueriesMax:      2,
		DefaultQueryRequestsMax:  3,
		DefaultOriginRequestsMax: 2,
	})
	ctx := context.Background()

	release, err := pool.AcquireQuery(ctx, "team-a")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	release()
}

func TestSemaphorePool_GlobalQueryLimitEnforced(t *testing.T) {
	t.Parallel()
	pool := guardrails.NewSemaphorePool(guardrails.SemaphorePoolConfig{
		GlobalRequestsMax:        100,
		GlobalQueriesMax:         2,
		DefaultNSQueriesMax:      10,
		DefaultQueryRequestsMax:  10,
		DefaultOriginRequestsMax: 10,
	})
	ctx := context.Background()

	release1, err := pool.AcquireQuery(ctx, "ns")
	if err != nil {
		t.Fatal(err)
	}
	release2, err := pool.AcquireQuery(ctx, "ns")
	if err != nil {
		t.Fatal(err)
	}

	// 3rd should fail immediately with a cancelled context.
	cancelCtx, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	_, err = pool.AcquireQuery(cancelCtx, "ns")
	if err == nil {
		t.Fatal("expected concurrency limit error on 3rd query")
	}

	release1()
	release2()
}

func TestSemaphorePool_AcquireReleaseRequest(t *testing.T) {
	t.Parallel()
	pool := guardrails.NewSemaphorePool(guardrails.SemaphorePoolConfig{
		GlobalRequestsMax:        10,
		GlobalQueriesMax:         10,
		DefaultNSQueriesMax:      5,
		DefaultQueryRequestsMax:  3,
		DefaultOriginRequestsMax: 2,
	})
	ctx := context.Background()

	release, err := pool.AcquireRequest(ctx, "query-1", "api.example.com:443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	release()
}
