package config

import "time"

// Default returns the most restrictive safe configuration.  Every guard rail
// is ON at its strictest default.  Admins may only relax values via an
// explicit admin config file — they can never exceed the compiled-in hard
// limits in internal/limits.
func Default() Config {
	return Config{
		SchemaVersion: "1.0",
		Engine: EngineConfig{
			InstanceID:  "default",
			Environment: "production",
			LogLevel:    "info",
		},
		Limits: LimitsConfig{
			Requests: RequestLimits{
				MaxRequestsPerQuery:        10,
				MaxDistinctOriginsPerQuery: 3,
				MaxWithBlocksPerQuery:      5,
				MaxRetryAttempts:           3,
				MaxSecretRefreshesPerQuery: 1,
				MaxRedirectsPerRequest:     3,
				AllowCrossOriginRedirects:  false,
			},
			Concurrency: ConcurrencyLimits{
				MaxConcurrentRequestsGlobal:      50,
				MaxConcurrentRequestsPerQuery:    5,
				MaxConcurrentRequestsPerOrigin:   2,
				MaxConcurrentQueriesGlobal:       20,
				MaxConcurrentQueriesPerNamespace: 10,
				ConnectionPoolSizePerOrigin:      10,
				IdleConnectionTTL:                30 * time.Second,
			},
			Timing: TimingLimits{
				RequestConnectTimeout:  5 * time.Second,
				RequestReadTimeout:     30 * time.Second,
				RequestWriteTimeout:    10 * time.Second,
				QueryWallClockTimeout:  60 * time.Second,
				PaginationTotalTimeout: 120 * time.Second,
				RetryBaseDelay:         1 * time.Second,
				RetryMaxDelay:          30 * time.Second,
				RetryAfterHonourMax:    60 * time.Second,
				RequestQueueTimeout:    10 * time.Second,
			},
			Body: BodyLimits{
				MaxRequestBodyBytes:             1 * 1024 * 1024,        // 1 MB
				MaxResponseBodyBytes:            10 * 1024 * 1024,       // 10 MB
				StreamingParseThreshold:         5 * 1024 * 1024,        // 5 MB
				MaxResponseHeaderCount:          100,
				MaxResponseHeaderValueBytes:     8192,
				MaxTotalBytesPerQuery:           100 * 1024 * 1024,      // 100 MB
				MaxTotalBytesPerNamespacePerMin: 500 * 1024 * 1024,      // 500 MB
			},
			Pagination: PaginationLimits{
				MaxPagesPerRequest:           100,
				MaxRowsPerQuery:              100_000,
				MaxRowsInMemory:              50_000,
				PaginationInfiniteLoopWindow: 5,
				MaxMergeSources:              10,
				MaxDeduplicateKeyCardinality: 500_000,
				DiskSpillEnabled:             false,
				DiskSpillDir:                 "",
				DiskSpillMaxBytes:            1 * 1024 * 1024 * 1024, // 1 GB
			},
		},
		Caching: CachingConfig{
			RequestCache: RequestCacheConfig{
				Enabled:      true,
				DefaultTTL:   0, // disabled by default; query must opt-in
				MaxTTL:       3600 * time.Second,
				MaxSizeBytes: 100 * 1024 * 1024, // 100 MB
				MaxEntries:   10_000,
				DefaultScope: "query",
			},
			ResponseCache: ResponseCacheConfig{
				Enabled:                 false, // admin must explicitly enable
				DefaultTTL:              300 * time.Second,
				MaxTTL:                  3600 * time.Second,
				StaleWhileRevalidateMax: 0,
				MaxSizeBytes:            500 * 1024 * 1024, // 500 MB
				MaxRowsPerEntry:         10_000,
				Backend:                 "memory",
				Redis: RedisCacheConfig{
					TLS: true,
				},
			},
			AdminPurgeAPI: AdminPurgeAPIConfig{
				Enabled:      true,
				RequireToken: true,
			},
		},
		Security: SecurityConfig{
			SSRFProtection: true,  // hardcoded; listed for audit visibility
			AllowedSchemes: []string{"https"},
			PrivateIPDenylist: PrivateIPDenylist{
				Enabled:         true,
				AdditionalCIDRs: nil,
			},
			PrivateIPAllowlist: nil,
			TLS: TLSConfig{
				MinVersion: "TLS1.2",
				VerifyCert: true,
			},
			Secrets: SecretsConfig{
				MaxRefsPerQuery: 5,
				ValueInLogs:     false, // hardcoded; cannot be true in any env
				Backend:         "env",
				Vault: VaultConfig{
					Mount:    "secret",
					TokenEnv: "VAULT_TOKEN",
				},
				K8s: K8sConfig{
					ServiceAccountTokenPath: "/var/run/secrets/kubernetes.io/serviceaccount/token",
				},
				AWSSSM: AWSSMConfig{
					Prefix: "/httpql/",
				},
			},
			MaxSecretRefsPerQuery: 5,
			MaxQueryPlanDepth:     10,
			AllowHTTPScheme:       false,
		},
		Audit: AuditConfig{
			LogAllRequests:    true,
			LogResponseStatus: true,
			LogRequestBody:    false,
			LogResponseBody:   false, // hardcoded; cannot be enabled
			LogPaginationHops: true,
			LogCacheEvents:    true,
			LogRedirectHops:   true,
			Sink:              "stdout",
			File: AuditFileConfig{
				Path:         "/var/log/httpql/audit.jsonl",
				RotateSizeMB: 100,
				RotateKeep:   7,
			},
			OTLP: AuditOTLPConfig{
				TLS: true,
			},
			Metrics: MetricsConfig{
				Enabled: true,
				Path:    "/metrics",
				Port:    9090,
			},
		},
		Namespaces: nil,
	}
}
