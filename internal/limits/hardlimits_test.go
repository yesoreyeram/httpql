package limits_test

import (
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/limits"
)

// TestHardLimitsArePositive ensures that all numeric hard limits are greater
// than zero — a zero limit would block all queries immediately.
func TestHardLimitsArePositive(t *testing.T) {
	t.Parallel()

	intCases := []struct {
		name  string
		value int
	}{
		{"HardMaxRequestsPerQuery", limits.HardMaxRequestsPerQuery},
		{"HardMaxDistinctOriginsPerQuery", limits.HardMaxDistinctOriginsPerQuery},
		{"HardMaxWithBlocksPerQuery", limits.HardMaxWithBlocksPerQuery},
		{"HardMaxRetryAttempts", limits.HardMaxRetryAttempts},
		{"HardMaxSecretRefreshesPerQuery", limits.HardMaxSecretRefreshesPerQuery},
		{"HardMaxRedirectsPerRequest", limits.HardMaxRedirectsPerRequest},
		{"HardMaxSecretRefsPerQuery", limits.HardMaxSecretRefsPerQuery},
		{"HardMaxConcurrentRequestsGlobal", limits.HardMaxConcurrentRequestsGlobal},
		{"HardMaxConcurrentRequestsPerQuery", limits.HardMaxConcurrentRequestsPerQuery},
		{"HardMaxConcurrentRequestsPerOrigin", limits.HardMaxConcurrentRequestsPerOrigin},
		{"HardMaxConcurrentQueriesGlobal", limits.HardMaxConcurrentQueriesGlobal},
		{"HardMaxConcurrentQueriesPerNamespace", limits.HardMaxConcurrentQueriesPerNamespace},
		{"HardConnectionPoolSizePerOrigin", limits.HardConnectionPoolSizePerOrigin},
		{"HardMaxRequestBodyBytes", limits.HardMaxRequestBodyBytes},
		{"HardMaxResponseBodyBytes", limits.HardMaxResponseBodyBytes},
		{"HardMaxResponseHeaderCount", limits.HardMaxResponseHeaderCount},
		{"HardMaxResponseHeaderValueBytes", limits.HardMaxResponseHeaderValueBytes},
		{"HardMaxTotalBytesPerQuery", limits.HardMaxTotalBytesPerQuery},
		{"HardMaxPagesPerRequest", limits.HardMaxPagesPerRequest},
		{"HardMaxRowsPerQuery", limits.HardMaxRowsPerQuery},
		{"HardMaxRowsInMemory", limits.HardMaxRowsInMemory},
		{"HardMaxQueryPlanDepth", limits.HardMaxQueryPlanDepth},
	}
	for _, tc := range intCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.value <= 0 {
				t.Errorf("%s must be > 0, got %d", tc.name, tc.value)
			}
		})
	}

	durationCases := []struct {
		name  string
		value time.Duration
	}{
		{"HardRequestConnectTimeout", limits.HardRequestConnectTimeout},
		{"HardRequestReadTimeout", limits.HardRequestReadTimeout},
		{"HardRequestWriteTimeout", limits.HardRequestWriteTimeout},
		{"HardQueryWallClockTimeout", limits.HardQueryWallClockTimeout},
		{"HardPaginationTotalTimeout", limits.HardPaginationTotalTimeout},
		{"HardRequestCacheMaxTTL", limits.HardRequestCacheMaxTTL},
		{"HardResponseCacheMaxTTL", limits.HardResponseCacheMaxTTL},
		{"HardResponseCacheSWRMax", limits.HardResponseCacheSWRMax},
	}
	for _, tc := range durationCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.value <= 0 {
				t.Errorf("%s must be > 0, got %v", tc.name, tc.value)
			}
		})
	}
}

// TestSecurityInvariantsAreEnabled verifies that all hardcoded security
// constants are in the safe (enabled) state.
func TestSecurityInvariantsAreEnabled(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		value bool
	}{
		{"AuthHeaderNeverCached", limits.AuthHeaderNeverCached},
		{"SecretValueNeverLogged", limits.SecretValueNeverLogged},
		{"TLSVerifyCertInProduction", limits.TLSVerifyCertInProduction},
		{"ResponseBodyNeverLogged", limits.ResponseBodyNeverLogged},
		{"NamespaceCacheIsolation", limits.NamespaceCacheIsolation},
		{"SSRFProtectionAlwaysEnabled", limits.SSRFProtectionAlwaysEnabled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !tc.value {
				t.Errorf("security invariant %s must be true", tc.name)
			}
		})
	}
}

// TestHardLimitsHierarchy checks that per-query limits are smaller than global
// limits, and per-origin limits are smaller than per-query limits.
func TestHardLimitsHierarchy(t *testing.T) {
	t.Parallel()

	if limits.HardMaxConcurrentRequestsGlobal <= limits.HardMaxConcurrentRequestsPerQuery {
		t.Errorf("global concurrent requests ceiling (%d) must exceed per-query ceiling (%d)",
			limits.HardMaxConcurrentRequestsGlobal, limits.HardMaxConcurrentRequestsPerQuery)
	}
	if limits.HardMaxConcurrentQueriesGlobal <= limits.HardMaxConcurrentQueriesPerNamespace {
		t.Errorf("global concurrent queries ceiling (%d) must exceed per-namespace ceiling (%d)",
			limits.HardMaxConcurrentQueriesGlobal, limits.HardMaxConcurrentQueriesPerNamespace)
	}
	if limits.HardResponseCacheMaxTTL <= limits.HardRequestCacheMaxTTL {
		t.Errorf("response cache max TTL (%v) should exceed request cache max TTL (%v)",
			limits.HardResponseCacheMaxTTL, limits.HardRequestCacheMaxTTL)
	}
}
