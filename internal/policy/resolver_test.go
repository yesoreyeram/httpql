package policy_test

import (
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/policy"
)

func defaultResolver() *policy.Resolver {
	return policy.NewResolver(config.Default())
}

// ─── Basic resolution ────────────────────────────────────────────────────────

func TestResolve_UnknownNamespaceReturnsGlobalDefaults(t *testing.T) {
	t.Parallel()
	r := defaultResolver()
	ep := r.Resolve("no-such-namespace")

	cfg := config.Default()
	if ep.MaxRequestsPerQuery != cfg.Limits.Requests.MaxRequestsPerQuery {
		t.Errorf("expected %d, got %d",
			cfg.Limits.Requests.MaxRequestsPerQuery, ep.MaxRequestsPerQuery)
	}
	if ep.QueryWallClockTimeout != cfg.Limits.Timing.QueryWallClockTimeout {
		t.Errorf("expected %v, got %v",
			cfg.Limits.Timing.QueryWallClockTimeout, ep.QueryWallClockTimeout)
	}
}

func TestResolve_NamespaceCanTightenRequestLimit(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Namespaces = []config.Namespace{
		{
			Name: "tight",
			Limits: config.LimitsConfig{
				Requests: config.RequestLimits{
					MaxRequestsPerQuery: 2, // global default is 10
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("tight")

	if ep.MaxRequestsPerQuery != 2 {
		t.Errorf("expected namespace override of 2, got %d", ep.MaxRequestsPerQuery)
	}
}

func TestResolve_NamespaceCannotExceedGlobal(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	globalMax := cfg.Limits.Requests.MaxRequestsPerQuery // e.g. 10

	cfg.Namespaces = []config.Namespace{
		{
			Name: "greedy",
			Limits: config.LimitsConfig{
				Requests: config.RequestLimits{
					MaxRequestsPerQuery: globalMax * 100, // way above global
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("greedy")

	// pickIntMin must have clamped this to the global maximum.
	if ep.MaxRequestsPerQuery > globalMax {
		t.Errorf("namespace override %d exceeds global max %d",
			ep.MaxRequestsPerQuery, globalMax)
	}
}

func TestResolve_NamespaceZeroValueInheritsGlobal(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Namespaces = []config.Namespace{
		{
			Name: "zero-ns",
			Limits: config.LimitsConfig{
				Requests: config.RequestLimits{
					MaxRequestsPerQuery: 0, // zero = not set; inherit global
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("zero-ns")

	if ep.MaxRequestsPerQuery != cfg.Limits.Requests.MaxRequestsPerQuery {
		t.Errorf("zero override should inherit global %d, got %d",
			cfg.Limits.Requests.MaxRequestsPerQuery, ep.MaxRequestsPerQuery)
	}
}

// ─── Security invariants ─────────────────────────────────────────────────────

func TestResolve_SSRFProtectionAlwaysEnabled(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Namespaces = []config.Namespace{
		{
			Name: "unsafe-ns",
			Security: config.SecurityConfig{
				SSRFProtection: false, // should be ignored
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("unsafe-ns")

	if !ep.SSRFProtectionEnabled {
		t.Error("SSRFProtectionEnabled must always be true regardless of namespace config")
	}
}

func TestResolve_CrossOriginRedirectCannotBeEnabledByNamespace(t *testing.T) {
	t.Parallel()

	cfg := config.Default() // AllowCrossOriginRedirects = false
	cfg.Namespaces = []config.Namespace{
		{
			Name: "redirect-ns",
			Limits: config.LimitsConfig{
				Requests: config.RequestLimits{
					AllowCrossOriginRedirects: true, // should be ignored
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("redirect-ns")

	if ep.AllowCrossOriginRedirects {
		t.Error("namespace must not enable cross-origin redirects if global has them disabled")
	}
}

func TestResolve_AllowedSchemesAreIntersected(t *testing.T) {
	t.Parallel()

	cfg := config.Default() // AllowedSchemes = ["https"]
	cfg.Security.AllowedSchemes = []string{"https", "http"}
	cfg.Namespaces = []config.Namespace{
		{
			Name: "https-only",
			Security: config.SecurityConfig{
				AllowedSchemes: []string{"https"},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("https-only")

	if len(ep.AllowedSchemes) != 1 || ep.AllowedSchemes[0] != "https" {
		t.Errorf("expected intersection [https], got %v", ep.AllowedSchemes)
	}
}

func TestResolve_NamespaceCannotAddNewScheme(t *testing.T) {
	t.Parallel()

	cfg := config.Default() // AllowedSchemes = ["https"]
	cfg.Namespaces = []config.Namespace{
		{
			Name: "add-ftp",
			Security: config.SecurityConfig{
				AllowedSchemes: []string{"https", "ftp"}, // ftp not in global
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("add-ftp")

	for _, s := range ep.AllowedSchemes {
		if s == "ftp" {
			t.Error("namespace must not be able to add schemes not present in global allowlist")
		}
	}
}

// ─── Caching ─────────────────────────────────────────────────────────────────

func TestResolve_ResponseCacheDisabledWhenGlobalDisabled(t *testing.T) {
	t.Parallel()

	cfg := config.Default() // ResponseCache.Enabled = false
	cfg.Namespaces = []config.Namespace{
		{
			Name: "wants-cache",
			Caching: config.CachingConfig{
				ResponseCache: config.ResponseCacheConfig{
					Enabled: true,
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("wants-cache")

	if ep.ResponseCacheEnabled {
		t.Error("namespace must not enable response cache when global has it disabled")
	}
}

func TestResolve_ResponseCacheEnabledWhenBothEnable(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Caching.ResponseCache.Enabled = true
	cfg.Namespaces = []config.Namespace{
		{
			Name: "cached-ns",
			Caching: config.CachingConfig{
				ResponseCache: config.ResponseCacheConfig{
					Enabled:    true,
					DefaultTTL: 60 * time.Second,
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("cached-ns")

	if !ep.ResponseCacheEnabled {
		t.Error("response cache should be enabled when both global and namespace enable it")
	}
	if ep.ResponseCacheDefaultTTL != 60*time.Second {
		t.Errorf("expected namespace TTL 60s, got %v", ep.ResponseCacheDefaultTTL)
	}
}

func TestResolve_ResponseCacheTTLCappedToMax(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Caching.ResponseCache.Enabled = true
	cfg.Caching.ResponseCache.MaxTTL = 300 * time.Second
	cfg.Namespaces = []config.Namespace{
		{
			Name: "long-ttl",
			Caching: config.CachingConfig{
				ResponseCache: config.ResponseCacheConfig{
					Enabled:    true,
					DefaultTTL: 9999 * time.Second, // exceeds global max
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("long-ttl")

	if ep.ResponseCacheDefaultTTL > cfg.Caching.ResponseCache.MaxTTL {
		t.Errorf("namespace TTL %v exceeds global max %v",
			ep.ResponseCacheDefaultTTL, cfg.Caching.ResponseCache.MaxTTL)
	}
}

// ─── Concurrency ─────────────────────────────────────────────────────────────

func TestResolve_NamespaceCanTightenConcurrency(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Namespaces = []config.Namespace{
		{
			Name: "serial",
			Limits: config.LimitsConfig{
				Concurrency: config.ConcurrencyLimits{
					MaxConcurrentRequestsPerQuery: 1,
				},
			},
		},
	}
	r := policy.NewResolver(cfg)
	ep := r.Resolve("serial")

	if ep.MaxConcurrentRequestsPerQuery != 1 {
		t.Errorf("expected concurrency=1, got %d", ep.MaxConcurrentRequestsPerQuery)
	}
}

// ─── Digest ───────────────────────────────────────────────────────────────────

func TestResolve_NamespaceIdentity(t *testing.T) {
	t.Parallel()
	r := defaultResolver()
	ep := r.Resolve("my-team")
	if ep.Namespace != "my-team" {
		t.Errorf("expected namespace='my-team', got %q", ep.Namespace)
	}
}
