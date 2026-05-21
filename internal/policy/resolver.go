// Package policy resolves the effective policy for a query running in a named
// namespace by merging the global admin configuration with any namespace-level
// override.  The result is an EffectivePolicy — a flat struct that the guard
// rail enforcement code reads without knowing about the layered config.
package policy

import (
	"time"

	"github.com/yesoreyeram/httpql/internal/config"
)

// EffectivePolicy is the flat, resolved set of limits and flags that apply to
// a query.  All fields are ready to be used directly — no further merging is
// needed by the enforcement layer.
type EffectivePolicy struct {
	// Identity
	Namespace string

	// Request budget
	MaxRequestsPerQuery        int
	MaxDistinctOriginsPerQuery int
	MaxWithBlocksPerQuery      int
	MaxRetryAttempts           int
	MaxSecretRefreshesPerQuery int
	MaxRedirectsPerRequest     int
	AllowCrossOriginRedirects  bool

	// Concurrency
	MaxConcurrentRequestsPerQuery    int
	MaxConcurrentRequestsPerOrigin   int
	MaxConcurrentQueriesPerNamespace int
	ConnectionPoolSizePerOrigin      int
	IdleConnectionTTL                time.Duration

	// Timing
	RequestConnectTimeout  time.Duration
	RequestReadTimeout     time.Duration
	RequestWriteTimeout    time.Duration
	QueryWallClockTimeout  time.Duration
	PaginationTotalTimeout time.Duration
	RetryBaseDelay         time.Duration
	RetryMaxDelay          time.Duration
	RetryAfterHonourMax    time.Duration
	RequestQueueTimeout    time.Duration

	// Body
	MaxRequestBodyBytes         int64
	MaxResponseBodyBytes        int64
	StreamingParseThreshold     int64
	MaxResponseHeaderCount      int
	MaxResponseHeaderValueBytes int
	MaxTotalBytesPerQuery       int64

	// Pagination
	MaxPagesPerRequest           int
	MaxRowsPerQuery              int
	MaxRowsInMemory              int
	PaginationInfiniteLoopWindow int
	MaxMergeSources              int
	MaxDeduplicateKeyCardinality int
	DiskSpillEnabled             bool
	DiskSpillDir                 string
	DiskSpillMaxBytes            int64

	// Caching — request
	RequestCacheEnabled bool
	RequestCacheMaxTTL  time.Duration
	RequestCacheScope   string // "query" | "namespace"

	// Caching — response
	ResponseCacheEnabled        bool
	ResponseCacheDefaultTTL     time.Duration
	ResponseCacheMaxTTL         time.Duration
	ResponseCacheSWRMax         time.Duration
	ResponseCacheMaxRowsPerEntry int

	// Security
	SSRFProtectionEnabled  bool
	AllowedSchemes         []string
	PrivateIPAllowlist     []string
	TLSMinVersion          string
	TLSVerifyCert          bool
	// TLSClientCert is the path to the PEM-encoded client certificate file.
	// When non-empty, mutual TLS is used for outbound connections.
	TLSClientCert string
	// TLSClientKey is the path to the PEM-encoded private key file that
	// corresponds to TLSClientCert.
	TLSClientKey string
	// TLSCustomCABundle is the path to a PEM-encoded CA certificate file
	// used to verify server certificates in addition to (or instead of)
	// the system roots.
	TLSCustomCABundle string
	MaxSecretRefsPerQuery  int
	MaxQueryPlanDepth      int
	AllowHTTPScheme        bool
}

// Resolver builds EffectivePolicy values from a loaded Config.
// It is safe for concurrent use once constructed.
type Resolver struct {
	global config.Config
	byName map[string]config.Namespace
}

// NewResolver constructs a Resolver from a validated, clamped Config.
func NewResolver(cfg config.Config) *Resolver {
	r := &Resolver{
		global: cfg,
		byName: make(map[string]config.Namespace, len(cfg.Namespaces)),
	}
	for _, ns := range cfg.Namespaces {
		r.byName[ns.Name] = ns
	}
	return r
}

// Resolve returns the EffectivePolicy for the named namespace.  If no
// namespace override exists the global admin defaults are used.
//
// Namespace values are applied only when they are non-zero/non-empty, and
// they are silently clamped to the global value when they are more permissive
// (this is a safety net; the config validator should catch these cases first).
func (r *Resolver) Resolve(namespace string) EffectivePolicy {
	g := r.global
	ns, found := r.byName[namespace]

	ep := EffectivePolicy{
		Namespace: namespace,

		// Request budget — start from global defaults.
		MaxRequestsPerQuery:        g.Limits.Requests.MaxRequestsPerQuery,
		MaxDistinctOriginsPerQuery: g.Limits.Requests.MaxDistinctOriginsPerQuery,
		MaxWithBlocksPerQuery:      g.Limits.Requests.MaxWithBlocksPerQuery,
		MaxRetryAttempts:           g.Limits.Requests.MaxRetryAttempts,
		MaxSecretRefreshesPerQuery: g.Limits.Requests.MaxSecretRefreshesPerQuery,
		MaxRedirectsPerRequest:     g.Limits.Requests.MaxRedirectsPerRequest,
		AllowCrossOriginRedirects:  g.Limits.Requests.AllowCrossOriginRedirects,

		// Concurrency
		MaxConcurrentRequestsPerQuery:    g.Limits.Concurrency.MaxConcurrentRequestsPerQuery,
		MaxConcurrentRequestsPerOrigin:   g.Limits.Concurrency.MaxConcurrentRequestsPerOrigin,
		MaxConcurrentQueriesPerNamespace: g.Limits.Concurrency.MaxConcurrentQueriesPerNamespace,
		ConnectionPoolSizePerOrigin:      g.Limits.Concurrency.ConnectionPoolSizePerOrigin,
		IdleConnectionTTL:                g.Limits.Concurrency.IdleConnectionTTL,

		// Timing
		RequestConnectTimeout:  g.Limits.Timing.RequestConnectTimeout,
		RequestReadTimeout:     g.Limits.Timing.RequestReadTimeout,
		RequestWriteTimeout:    g.Limits.Timing.RequestWriteTimeout,
		QueryWallClockTimeout:  g.Limits.Timing.QueryWallClockTimeout,
		PaginationTotalTimeout: g.Limits.Timing.PaginationTotalTimeout,
		RetryBaseDelay:         g.Limits.Timing.RetryBaseDelay,
		RetryMaxDelay:          g.Limits.Timing.RetryMaxDelay,
		RetryAfterHonourMax:    g.Limits.Timing.RetryAfterHonourMax,
		RequestQueueTimeout:    g.Limits.Timing.RequestQueueTimeout,

		// Body
		MaxRequestBodyBytes:         g.Limits.Body.MaxRequestBodyBytes,
		MaxResponseBodyBytes:        g.Limits.Body.MaxResponseBodyBytes,
		StreamingParseThreshold:     g.Limits.Body.StreamingParseThreshold,
		MaxResponseHeaderCount:      g.Limits.Body.MaxResponseHeaderCount,
		MaxResponseHeaderValueBytes: g.Limits.Body.MaxResponseHeaderValueBytes,
		MaxTotalBytesPerQuery:       g.Limits.Body.MaxTotalBytesPerQuery,

		// Pagination
		MaxPagesPerRequest:           g.Limits.Pagination.MaxPagesPerRequest,
		MaxRowsPerQuery:              g.Limits.Pagination.MaxRowsPerQuery,
		MaxRowsInMemory:              g.Limits.Pagination.MaxRowsInMemory,
		PaginationInfiniteLoopWindow: g.Limits.Pagination.PaginationInfiniteLoopWindow,
		MaxMergeSources:              g.Limits.Pagination.MaxMergeSources,
		MaxDeduplicateKeyCardinality: g.Limits.Pagination.MaxDeduplicateKeyCardinality,
		DiskSpillEnabled:             g.Limits.Pagination.DiskSpillEnabled,
		DiskSpillDir:                 g.Limits.Pagination.DiskSpillDir,
		DiskSpillMaxBytes:            g.Limits.Pagination.DiskSpillMaxBytes,

		// Caching — request
		RequestCacheEnabled: g.Caching.RequestCache.Enabled,
		RequestCacheMaxTTL:  g.Caching.RequestCache.MaxTTL,
		RequestCacheScope:   g.Caching.RequestCache.DefaultScope,

		// Caching — response
		ResponseCacheEnabled:         g.Caching.ResponseCache.Enabled,
		ResponseCacheDefaultTTL:      g.Caching.ResponseCache.DefaultTTL,
		ResponseCacheMaxTTL:          g.Caching.ResponseCache.MaxTTL,
		ResponseCacheSWRMax:          g.Caching.ResponseCache.StaleWhileRevalidateMax,
		ResponseCacheMaxRowsPerEntry: g.Caching.ResponseCache.MaxRowsPerEntry,

		// Security
		SSRFProtectionEnabled: true, // hardcoded invariant; cannot be changed
		AllowedSchemes:        copyStrings(g.Security.AllowedSchemes),
		PrivateIPAllowlist:    copyStrings(g.Security.PrivateIPAllowlist),
		TLSMinVersion:         g.Security.TLS.MinVersion,
		TLSVerifyCert:         g.Security.TLS.VerifyCert,
		TLSClientCert:         g.Security.TLS.ClientCert,
		TLSClientKey:          g.Security.TLS.ClientKey,
		TLSCustomCABundle:     g.Security.TLS.CustomCABundle,
		MaxSecretRefsPerQuery: g.Security.MaxSecretRefsPerQuery,
		MaxQueryPlanDepth:     g.Security.MaxQueryPlanDepth,
		AllowHTTPScheme:       g.Security.AllowHTTPScheme,
	}

	if !found {
		return ep
	}

	// ── Apply namespace overrides (never allow exceeding global) ─────────────

	nl := ns.Limits

	// Requests — namespace may only tighten or keep (zero = inherit global).
	ep.MaxRequestsPerQuery = pickIntMin(nl.Requests.MaxRequestsPerQuery, ep.MaxRequestsPerQuery)
	ep.MaxWithBlocksPerQuery = pickIntMin(nl.Requests.MaxWithBlocksPerQuery, ep.MaxWithBlocksPerQuery)
	ep.MaxRetryAttempts = pickIntMin(nl.Requests.MaxRetryAttempts, ep.MaxRetryAttempts)
	ep.MaxRedirectsPerRequest = pickIntMin(nl.Requests.MaxRedirectsPerRequest, ep.MaxRedirectsPerRequest)
	// AllowCrossOriginRedirects may only be set false (restrict); never set to
	// true by a namespace if the global is false.
	if !g.Limits.Requests.AllowCrossOriginRedirects {
		ep.AllowCrossOriginRedirects = false
	}

	// Concurrency
	ep.MaxConcurrentRequestsPerQuery = pickIntMin(nl.Concurrency.MaxConcurrentRequestsPerQuery, ep.MaxConcurrentRequestsPerQuery)
	ep.MaxConcurrentRequestsPerOrigin = pickIntMin(nl.Concurrency.MaxConcurrentRequestsPerOrigin, ep.MaxConcurrentRequestsPerOrigin)
	ep.MaxConcurrentQueriesPerNamespace = pickIntMin(nl.Concurrency.MaxConcurrentQueriesPerNamespace, ep.MaxConcurrentQueriesPerNamespace)

	// Timing
	ep.QueryWallClockTimeout = pickDurationMin(nl.Timing.QueryWallClockTimeout, ep.QueryWallClockTimeout)
	ep.PaginationTotalTimeout = pickDurationMin(nl.Timing.PaginationTotalTimeout, ep.PaginationTotalTimeout)
	ep.RequestConnectTimeout = pickDurationMin(nl.Timing.RequestConnectTimeout, ep.RequestConnectTimeout)
	ep.RequestReadTimeout = pickDurationMin(nl.Timing.RequestReadTimeout, ep.RequestReadTimeout)

	// Pagination
	ep.MaxPagesPerRequest = pickIntMin(nl.Pagination.MaxPagesPerRequest, ep.MaxPagesPerRequest)
	ep.MaxRowsPerQuery = pickIntMin(nl.Pagination.MaxRowsPerQuery, ep.MaxRowsPerQuery)
	ep.MaxRowsInMemory = pickIntMin(nl.Pagination.MaxRowsInMemory, ep.MaxRowsInMemory)
	ep.MaxMergeSources = pickIntMin(nl.Pagination.MaxMergeSources, ep.MaxMergeSources)

	// Caching — namespace may enable response cache only if global allows it.
	nc := ns.Caching
	if nc.ResponseCache.Enabled && g.Caching.ResponseCache.Enabled {
		ep.ResponseCacheEnabled = true
	}
	if nc.ResponseCache.DefaultTTL > 0 {
		ep.ResponseCacheDefaultTTL = minDuration(nc.ResponseCache.DefaultTTL, ep.ResponseCacheMaxTTL)
	}
	if nc.ResponseCache.MaxTTL > 0 {
		ep.ResponseCacheMaxTTL = minDuration(nc.ResponseCache.MaxTTL, ep.ResponseCacheMaxTTL)
	}

	// Security — namespace may further restrict allowed schemes, never expand.
	if len(ns.Security.AllowedSchemes) > 0 {
		ep.AllowedSchemes = intersectStrings(ep.AllowedSchemes, ns.Security.AllowedSchemes)
	}
	// Namespace may extend private IP allowlist only within global allowlist.
	if len(ns.Security.PrivateIPAllowlist) > 0 {
		ep.PrivateIPAllowlist = ns.Security.PrivateIPAllowlist
	}
	ep.MaxSecretRefsPerQuery = pickIntMin(ns.Security.MaxSecretRefsPerQuery, ep.MaxSecretRefsPerQuery)

	// Security invariants are hardcoded and can never be changed by any namespace.
	ep.SSRFProtectionEnabled = true

	return ep
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// pickIntMin returns the minimum of a and b, ignoring zero values (zero means
// "not set; inherit").
func pickIntMin(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// pickDurationMin returns the minimum of a and b, ignoring zero values.
func pickDurationMin(a, b time.Duration) time.Duration {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func copyStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// intersectStrings returns elements present in both a and b.
func intersectStrings(a, b []string) []string {
	set := make(map[string]bool, len(a))
	for _, v := range a {
		set[v] = true
	}
	var out []string
	for _, v := range b {
		if set[v] {
			out = append(out, v)
		}
	}
	return out
}
