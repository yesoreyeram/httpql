package guardrails

import (
	"net"
	"net/url"
	"strings"

	"github.com/yesoreyeram/httpql/internal/policy"
)

// QueryPlan is the static information the planner validates before any HTTP
// request is issued.  It is produced by the query parser and consumed by
// Validate().
type QueryPlan struct {
	// Namespace this query runs in.
	Namespace string

	// WithBlocks is the number of datasource WITH blocks.
	WithBlocks int

	// EstimatedMaxPages is the maximum number of pagination pages any single
	// WITH block may produce (upper bound).
	EstimatedMaxPages int

	// EstimatedMaxRowsPerPage is the upper bound of rows returned per page.
	EstimatedMaxRowsPerPage int

	// ConcurrencyHint is the CONCURRENCY N query hint (0 = not specified).
	ConcurrencyHint int

	// QueryTimeoutHint is the QUERY_TIMEOUT hint (0 = not specified).
	QueryTimeoutHint int

	// RequestCacheTTLHint is the REQUEST_CACHE TTL hint in seconds (0 = not set).
	RequestCacheTTLHint int

	// ResponseCacheTTLHint is the CACHE TTL hint in seconds (0 = not set).
	ResponseCacheTTLHint int

	// MaxRowsHint is the STOP_WHEN TOTAL_ITEMS >= N hint (0 = not set).
	MaxRowsHint int

	// MaxPagesHint is the STOP_WHEN PAGE_COUNT >= N hint (0 = not set).
	MaxPagesHint int

	// RetryHint is the RETRY N hint (0 = not set).
	RetryHint int

	// RedirectMaxHint is the REDIRECTS FOLLOW MAX N hint (0 = not set).
	RedirectMaxHint int

	// URLs are all destination URLs referenced in the plan.
	URLs []string

	// SecretRefs is the number of secret references in the query.
	SecretRefs int

	// PlanDepth is the nesting depth of the query plan.
	PlanDepth int

	// HasCyclicDependency is set by the parser if a DEPENDS_ON cycle is detected.
	HasCyclicDependency bool
}

// PlanValidationResult is the output of Validate().
type PlanValidationResult struct {
	Allowed bool
	Checks  []PolicyCheck
}

// PolicyCheck is the result of a single plan-time policy check.
type PolicyCheck struct {
	Parameter string
	Estimated interface{}
	Status    string // "within_limit" | "exceeds_limit" | "using_default" | "pass" | "blocked"
	Error     *PolicyError
}

// Validate runs the complete plan-time validation pipeline against the
// effective policy for the query's namespace.  It never touches the network.
// All checks are O(1) or O(plan depth).
//
// If the plan is not allowed, the returned PlanValidationResult has Allowed=false
// and one or more checks with Status "exceeds_limit".  The returned error is
// the first hard violation encountered (for caller convenience).
func Validate(plan QueryPlan, ep policy.EffectivePolicy) (PlanValidationResult, error) {
	var checks []PolicyCheck
	var firstErr *PolicyError

	record := func(c PolicyCheck) {
		checks = append(checks, c)
		if c.Error != nil && firstErr == nil {
			firstErr = c.Error
		}
	}

	// ── Step 2: Cyclic dependency ─────────────────────────────────────────
	if plan.HasCyclicDependency {
		e := &PolicyError{Code: ErrCyclicDependency, Detail: "query plan contains a cyclic DEPENDS_ON reference"}
		record(PolicyCheck{Parameter: "depends_on", Status: "blocked", Error: e})
	}

	// ── Step 3: Max request count ─────────────────────────────────────────
	retries := plan.RetryHint
	if retries <= 0 {
		retries = 1
	}
	pages := plan.EstimatedMaxPages
	if pages <= 0 {
		pages = 1
	}
	maxRequests := plan.WithBlocks * pages * retries
	if maxRequests > ep.MaxRequestsPerQuery {
		e := &PolicyError{
			Code:      ErrPolicyLimitExceeded,
			Parameter: "max_requests_per_query",
			Requested: maxRequests,
			Detail:    "estimated request count exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "max_requests_per_query", Estimated: maxRequests, Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "max_requests_per_query", Estimated: maxRequests, Status: "within_limit"})
	}

	// ── Step 4: Concurrency ───────────────────────────────────────────────
	concurrency := plan.ConcurrencyHint
	if concurrency <= 0 {
		concurrency = plan.WithBlocks
	}
	if concurrency > ep.MaxConcurrentRequestsPerQuery {
		e := &PolicyError{
			Code:      ErrPolicyLimitExceeded,
			Parameter: "max_concurrent_requests_per_query",
			Requested: concurrency,
			Detail:    "concurrency hint exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "max_concurrent_requests_per_query", Estimated: concurrency, Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "max_concurrent_requests_per_query", Estimated: concurrency, Status: "within_limit"})
	}

	// ── Step 5: Timeout hints ─────────────────────────────────────────────
	if plan.QueryTimeoutHint > 0 {
		hintDur := plan.QueryTimeoutHint
		maxSecs := int(ep.QueryWallClockTimeout.Seconds())
		if hintDur > maxSecs {
			e := &PolicyError{
				Code:      ErrPolicyLimitExceeded,
				Parameter: "query_wall_clock_timeout",
				Requested: hintDur,
				Detail:    "QUERY_TIMEOUT hint exceeds configured maximum for this namespace",
			}
			record(PolicyCheck{Parameter: "query_wall_clock_timeout", Estimated: hintDur, Status: "exceeds_limit", Error: e})
		} else {
			record(PolicyCheck{Parameter: "query_wall_clock_timeout", Estimated: hintDur, Status: "within_limit"})
		}
	} else {
		record(PolicyCheck{Parameter: "query_wall_clock_timeout", Status: "using_default"})
	}

	// ── Step 6: Redirect max ──────────────────────────────────────────────
	if plan.RedirectMaxHint > 0 && plan.RedirectMaxHint > ep.MaxRedirectsPerRequest {
		e := &PolicyError{
			Code:      ErrPolicyLimitExceeded,
			Parameter: "max_redirects_per_request",
			Requested: plan.RedirectMaxHint,
			Detail:    "REDIRECTS FOLLOW MAX hint exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "max_redirects_per_request", Estimated: plan.RedirectMaxHint, Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "max_redirects_per_request", Status: "within_limit"})
	}

	// ── Step 7: SSRF & scheme checks on all URLs ──────────────────────────
	origins := make(map[string]bool)
	for _, rawURL := range plan.URLs {
		u, err := url.Parse(rawURL)
		if err != nil {
			e := &PolicyError{
				Code:      ErrSSRFBlocked,
				Parameter: "url",
				Requested: rawURL,
				Detail:    "could not parse URL",
			}
			record(PolicyCheck{Parameter: "ssrf_check", Estimated: rawURL, Status: "blocked", Error: e})
			continue
		}

		// Scheme check
		scheme := strings.ToLower(u.Scheme)
		if !schemeAllowed(scheme, ep.AllowedSchemes) {
			e := &PolicyError{
				Code:      ErrSchemeNotAllowed,
				Parameter: "url.scheme",
				Requested: scheme,
				Detail:    "URL scheme is not in the allowed schemes list for this namespace",
			}
			record(PolicyCheck{Parameter: "ssrf_check", Estimated: rawURL, Status: "blocked", Error: e})
			continue
		}

		// SSRF check — block private/loopback IPs
		if ep.SSRFProtectionEnabled {
			host := u.Hostname()
			if err := checkSSRF(host, ep.PrivateIPAllowlist); err != nil {
				record(PolicyCheck{Parameter: "ssrf_check", Estimated: rawURL, Status: "blocked", Error: err})
				continue
			}
		}

		record(PolicyCheck{Parameter: "ssrf_check", Estimated: rawURL, Status: "pass"})
		origins[u.Host] = true
	}

	// ── Step 8: Distinct origins ──────────────────────────────────────────
	if len(origins) > ep.MaxDistinctOriginsPerQuery {
		e := &PolicyError{
			Code:      ErrPolicyLimitExceeded,
			Parameter: "max_distinct_origins_per_query",
			Requested: len(origins),
			Detail:    "number of distinct origins exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "max_distinct_origins_per_query", Estimated: len(origins), Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "max_distinct_origins_per_query", Estimated: len(origins), Status: "within_limit"})
	}

	// ── Step 9: Secret refs ───────────────────────────────────────────────
	if plan.SecretRefs > ep.MaxSecretRefsPerQuery {
		e := &PolicyError{
			Code:      ErrPolicyLimitExceeded,
			Parameter: "max_secret_refs_per_query",
			Requested: plan.SecretRefs,
			Detail:    "number of secret references exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "secret_refs", Estimated: plan.SecretRefs, Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "secret_refs", Estimated: plan.SecretRefs, Status: "within_limit"})
	}

	// ── Step 10: Pagination hints ─────────────────────────────────────────
	if plan.MaxPagesHint > 0 && plan.MaxPagesHint > ep.MaxPagesPerRequest {
		e := &PolicyError{
			Code:      ErrPolicyLimitExceeded,
			Parameter: "pagination.max_pages",
			Requested: plan.MaxPagesHint,
			Detail:    "STOP_WHEN PAGE_COUNT hint exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "pagination.max_pages", Estimated: plan.MaxPagesHint, Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "pagination.max_pages", Status: "within_limit"})
	}

	if plan.MaxRowsHint > 0 && plan.MaxRowsHint > ep.MaxRowsPerQuery {
		e := &PolicyError{
			Code:      ErrPolicyLimitExceeded,
			Parameter: "pagination.max_rows",
			Requested: plan.MaxRowsHint,
			Detail:    "STOP_WHEN TOTAL_ITEMS hint exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "pagination.max_rows", Estimated: plan.MaxRowsHint, Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "pagination.max_rows", Status: "within_limit"})
	}

	// ── Step 11: Cache TTL hints ───────────────────────────────────────────
	if plan.RequestCacheTTLHint > 0 {
		maxSecs := int(ep.RequestCacheMaxTTL.Seconds())
		if plan.RequestCacheTTLHint > maxSecs {
			e := &PolicyError{
				Code:      ErrPolicyLimitExceeded,
				Parameter: "request_cache_ttl",
				Requested: plan.RequestCacheTTLHint,
				Detail:    "REQUEST_CACHE TTL hint exceeds configured maximum for this namespace",
			}
			record(PolicyCheck{Parameter: "request_cache_ttl", Estimated: plan.RequestCacheTTLHint, Status: "exceeds_limit", Error: e})
		} else {
			record(PolicyCheck{Parameter: "request_cache_ttl", Estimated: plan.RequestCacheTTLHint, Status: "within_limit"})
		}
	}

	if plan.ResponseCacheTTLHint > 0 {
		if !ep.ResponseCacheEnabled {
			e := &PolicyError{
				Code:      ErrPolicyLimitExceeded,
				Parameter: "response_cache_ttl",
				Requested: plan.ResponseCacheTTLHint,
				Detail:    "CACHE TTL hint used but response caching is not enabled for this namespace",
			}
			record(PolicyCheck{Parameter: "response_cache_ttl", Estimated: plan.ResponseCacheTTLHint, Status: "exceeds_limit", Error: e})
		} else {
			maxSecs := int(ep.ResponseCacheMaxTTL.Seconds())
			if plan.ResponseCacheTTLHint > maxSecs {
				e := &PolicyError{
					Code:      ErrPolicyLimitExceeded,
					Parameter: "response_cache_ttl",
					Requested: plan.ResponseCacheTTLHint,
					Detail:    "CACHE TTL hint exceeds configured maximum for this namespace",
				}
				record(PolicyCheck{Parameter: "response_cache_ttl", Estimated: plan.ResponseCacheTTLHint, Status: "exceeds_limit", Error: e})
			} else {
				record(PolicyCheck{Parameter: "response_cache_ttl", Estimated: plan.ResponseCacheTTLHint, Status: "within_limit"})
			}
		}
	}

	// ── Step 12/13: Plan depth ────────────────────────────────────────────
	if plan.PlanDepth > ep.MaxQueryPlanDepth {
		e := &PolicyError{
			Code:      ErrQueryTooDeep,
			Parameter: "max_query_plan_depth",
			Requested: plan.PlanDepth,
			Detail:    "query plan nesting depth exceeds configured maximum for this namespace",
		}
		record(PolicyCheck{Parameter: "max_query_plan_depth", Estimated: plan.PlanDepth, Status: "exceeds_limit", Error: e})
	} else {
		record(PolicyCheck{Parameter: "max_query_plan_depth", Estimated: plan.PlanDepth, Status: "within_limit"})
	}

	allowed := firstErr == nil
	var retErr error
	if firstErr != nil {
		retErr = firstErr
	}
	return PlanValidationResult{Allowed: allowed, Checks: checks}, retErr
}

// ─── SSRF helpers ─────────────────────────────────────────────────────────────

// privateRanges lists RFC-1918, loopback, link-local, and other non-routable
// IP ranges that are blocked by default.
var privateRanges []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",    // loopback
		"::1/128",         // IPv6 loopback
		"169.254.0.0/16",  // link-local
		"fe80::/10",       // IPv6 link-local
		"fc00::/7",        // IPv6 unique local
		"100.64.0.0/10",   // shared address space (RFC 6598)
		"192.0.0.0/24",    // IETF protocol assignments
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // reserved
		"0.0.0.0/8",       // "this" network
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateRanges = append(privateRanges, ipNet)
		}
	}
}

// checkSSRF returns a PolicyError if host resolves to or is a private/loopback
// address not in the allowlist.  It does NOT perform DNS resolution (that would
// introduce latency and TOCTOU issues); it only checks literal IP addresses.
// The engine's HTTP client must be configured with an IP-level dialer check for
// full SSRF protection after DNS resolution.
func checkSSRF(host string, allowlist []string) *PolicyError {
	ip := net.ParseIP(host)
	if ip == nil {
		// Non-IP hostname — allow; SSRF check happens at dial time in the
		// HTTP transport layer.
		return nil
	}

	// Check allowlist first.
	for _, cidr := range allowlist {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if ipNet.Contains(ip) {
			return nil
		}
	}

	// Check against all private ranges.
	for _, r := range privateRanges {
		if r.Contains(ip) {
			return &PolicyError{
				Code:      ErrSSRFBlocked,
				Parameter: "url.host",
				Requested: host,
				Detail:    "request to private/reserved IP address is blocked by SSRF protection",
			}
		}
	}
	return nil
}

func schemeAllowed(scheme string, allowed []string) bool {
	for _, s := range allowed {
		if strings.EqualFold(s, scheme) {
			return true
		}
	}
	return false
}
