// Package limits defines the compiled-in absolute ceilings for all guard rail
// parameters.  These values are constants — they can never be changed at
// runtime, via config, or via any query hint.  Admin-supplied configuration
// values are silently clamped to these ceilings at startup.
package limits

import "time"

// ─── Family R — Request Budget ───────────────────────────────────────────────

const (
	// HardMaxRequestsPerQuery is the absolute maximum number of HTTP requests
	// that a single query execution may issue (including retries and pagination).
	HardMaxRequestsPerQuery = 500

	// HardMaxDistinctOriginsPerQuery caps the number of distinct host:port
	// combinations that a single query may contact.
	HardMaxDistinctOriginsPerQuery = 10

	// HardMaxWithBlocksPerQuery caps the number of WITH datasource blocks.
	HardMaxWithBlocksPerQuery = 20

	// HardMaxRetryAttempts is the most retries allowed per individual request.
	HardMaxRetryAttempts = 10

	// HardMaxSecretRefreshesPerQuery caps how many times secrets may be
	// refreshed during a single query execution.
	HardMaxSecretRefreshesPerQuery = 5

	// HardMaxRedirectsPerRequest is the maximum number of HTTP redirects the
	// engine will follow for a single request.
	HardMaxRedirectsPerRequest = 20

	// HardMaxSecretRefsPerQuery is the maximum number of secret references
	// allowed in a single query.
	HardMaxSecretRefsPerQuery = 20
)

// ─── Family C — Concurrency ───────────────────────────────────────────────────

const (
	HardMaxConcurrentRequestsGlobal      = 1000
	HardMaxConcurrentRequestsPerQuery    = 200
	HardMaxConcurrentRequestsPerOrigin   = 100
	HardMaxConcurrentQueriesGlobal       = 500
	HardMaxConcurrentQueriesPerNamespace = 100
	HardConnectionPoolSizePerOrigin      = 100
)

// ─── Family T — Timing ────────────────────────────────────────────────────────

const (
	HardRequestConnectTimeout    = 60 * time.Second
	HardRequestReadTimeout       = 300 * time.Second
	HardRequestWriteTimeout      = 60 * time.Second
	HardQueryWallClockTimeout    = 600 * time.Second
	HardPaginationTotalTimeout   = 1800 * time.Second
	HardRetryBaseDelay           = 60 * time.Second
	HardRetryMaxDelay            = 300 * time.Second
	HardRetryAfterHonourMax      = 3600 * time.Second
	HardRequestQueueTimeout      = 60 * time.Second
	HardIdleConnectionTTL        = time.Duration(0) // no engine-level ceiling; pool enforces
)

// ─── Family B — Body & Bandwidth ─────────────────────────────────────────────

const (
	HardMaxRequestBodyBytes              = 100 * 1024 * 1024       // 100 MB
	HardMaxResponseBodyBytes             = 500 * 1024 * 1024       // 500 MB
	HardStreamingParseThreshold          = 500 * 1024 * 1024       // 500 MB
	HardMaxResponseHeaderCount           = 500
	HardMaxResponseHeaderValueBytes      = 65535
	HardMaxTotalBytesPerQuery            = 10 * 1024 * 1024 * 1024 // 10 GB
	HardMaxTotalBytesPerNamespacePerMin  = 100 * 1024 * 1024 * 1024 // 100 GB
)

// ─── Family P — Pagination ────────────────────────────────────────────────────

const (
	HardMaxPagesPerRequest           = 10_000
	HardMaxRowsPerQuery              = 10_000_000
	HardMaxRowsInMemory              = 5_000_000
	HardPaginationInfiniteLoopWindow = 100 // max duplicate cursor window
	HardMaxMergeSources              = 50
	HardMaxDeduplicateKeyCardinality = 10_000_000
)

// ─── Family K — Caching ───────────────────────────────────────────────────────

const (
	HardRequestCacheMaxTTL    = 3600 * time.Second
	HardRequestCacheMaxBytes  = 10 * 1024 * 1024 * 1024 // 10 GB
	HardRequestCacheMaxEntries = 1_000_000

	HardResponseCacheMaxTTL              = 86400 * time.Second
	HardResponseCacheSWRMax              = 3600 * time.Second
	HardResponseCacheMaxBytes            = 50 * 1024 * 1024 * 1024 // 50 GB
	HardResponseCacheMaxRowsPerEntry     = 1_000_000
)

// ─── Family S — Security ─────────────────────────────────────────────────────

const (
	HardMaxQueryPlanDepth = 20
)

// ─── Hardcoded security invariants (cannot be changed by any config) ─────────

// These booleans are not runtime-configurable; they are listed here for
// documentation and for use in compile-time assertions.
const (
	// AuthHeaderNeverCached is a compile-time invariant: auth values are never
	// stored in any cache entry.
	AuthHeaderNeverCached = true

	// SecretValueNeverLogged ensures secret values never appear in audit logs.
	SecretValueNeverLogged = true

	// TLSVerifyCertInProduction ensures TLS certificate verification is always
	// on in production environments.
	TLSVerifyCertInProduction = true

	// ResponseBodyNeverLogged ensures response bodies never appear in audit logs.
	ResponseBodyNeverLogged = true

	// NamespaceCacheIsolation ensures one namespace can never read another's cache.
	NamespaceCacheIsolation = true

	// SSRFProtectionAlwaysEnabled ensures SSRF protection cannot be disabled
	// even by admin configuration (only specific allowlist CIDRs may be added).
	SSRFProtectionAlwaysEnabled = true
)
