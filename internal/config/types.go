// Package config defines all admin-configurable parameters for the httpql
// engine.  The Config type is the single source of truth.  Default values
// represent the most restrictive safe settings — any relaxation must be
// explicit in the config file.
package config

import "time"

// ─── Top-level ───────────────────────────────────────────────────────────────

// Config is the root configuration object loaded from httpql-engine.yaml.
// JSON/YAML tags are provided for deserialization; snake_case matches the
// documented admin config file format.
type Config struct {
	SchemaVersion string         `yaml:"schema_version" json:"schema_version"`
	Engine        EngineConfig   `yaml:"engine"         json:"engine"`
	Limits        LimitsConfig   `yaml:"limits"         json:"limits"`
	Caching       CachingConfig  `yaml:"caching"        json:"caching"`
	Security      SecurityConfig `yaml:"security"       json:"security"`
	Audit         AuditConfig    `yaml:"audit"          json:"audit"`
	Namespaces    []Namespace    `yaml:"namespaces"     json:"namespaces"`
}

// ─── Engine identity ─────────────────────────────────────────────────────────

// EngineConfig holds non-functional metadata about the running engine instance.
type EngineConfig struct {
	InstanceID  string `yaml:"instance_id"  json:"instance_id"`
	Environment string `yaml:"environment"  json:"environment"` // production | staging | development
	LogLevel    string `yaml:"log_level"    json:"log_level"`   // trace|debug|info|warn|error
}

// ─── Limits ──────────────────────────────────────────────────────────────────

// LimitsConfig groups all rate/resource limit sub-configs.
type LimitsConfig struct {
	Requests    RequestLimits    `yaml:"requests"    json:"requests"`
	Concurrency ConcurrencyLimits `yaml:"concurrency" json:"concurrency"`
	Timing      TimingLimits     `yaml:"timing"      json:"timing"`
	Body        BodyLimits       `yaml:"body"        json:"body"`
	Pagination  PaginationLimits `yaml:"pagination"  json:"pagination"`
}

// RequestLimits controls the HTTP request budget for a query.
type RequestLimits struct {
	MaxRequestsPerQuery        int  `yaml:"max_requests_per_query"         json:"max_requests_per_query"`
	MaxDistinctOriginsPerQuery int  `yaml:"max_distinct_origins_per_query" json:"max_distinct_origins_per_query"`
	MaxWithBlocksPerQuery      int  `yaml:"max_with_blocks_per_query"      json:"max_with_blocks_per_query"`
	MaxRetryAttempts           int  `yaml:"max_retry_attempts"             json:"max_retry_attempts"`
	MaxSecretRefreshesPerQuery int  `yaml:"max_secret_refreshes_per_query" json:"max_secret_refreshes_per_query"`
	MaxRedirectsPerRequest     int  `yaml:"max_redirects_per_request"      json:"max_redirects_per_request"`
	AllowCrossOriginRedirects  bool `yaml:"allow_cross_origin_redirects"   json:"allow_cross_origin_redirects"`
}

// ConcurrencyLimits controls in-flight parallelism at every scope level.
type ConcurrencyLimits struct {
	MaxConcurrentRequestsGlobal      int           `yaml:"max_concurrent_requests_global"       json:"max_concurrent_requests_global"`
	MaxConcurrentRequestsPerQuery    int           `yaml:"max_concurrent_requests_per_query"    json:"max_concurrent_requests_per_query"`
	MaxConcurrentRequestsPerOrigin   int           `yaml:"max_concurrent_requests_per_origin"   json:"max_concurrent_requests_per_origin"`
	MaxConcurrentQueriesGlobal       int           `yaml:"max_concurrent_queries_global"        json:"max_concurrent_queries_global"`
	MaxConcurrentQueriesPerNamespace int           `yaml:"max_concurrent_queries_per_namespace" json:"max_concurrent_queries_per_namespace"`
	ConnectionPoolSizePerOrigin      int           `yaml:"connection_pool_size_per_origin"      json:"connection_pool_size_per_origin"`
	IdleConnectionTTL                time.Duration `yaml:"idle_connection_ttl"                  json:"idle_connection_ttl"`
}

// TimingLimits controls all timeout and delay windows.
type TimingLimits struct {
	RequestConnectTimeout  time.Duration `yaml:"request_connect_timeout"   json:"request_connect_timeout"`
	RequestReadTimeout     time.Duration `yaml:"request_read_timeout"      json:"request_read_timeout"`
	RequestWriteTimeout    time.Duration `yaml:"request_write_timeout"     json:"request_write_timeout"`
	QueryWallClockTimeout  time.Duration `yaml:"query_wall_clock_timeout"  json:"query_wall_clock_timeout"`
	PaginationTotalTimeout time.Duration `yaml:"pagination_total_timeout"  json:"pagination_total_timeout"`
	RetryBaseDelay         time.Duration `yaml:"retry_base_delay"          json:"retry_base_delay"`
	RetryMaxDelay          time.Duration `yaml:"retry_max_delay"           json:"retry_max_delay"`
	RetryAfterHonourMax    time.Duration `yaml:"retry_after_honour_max"    json:"retry_after_honour_max"`
	RequestQueueTimeout    time.Duration `yaml:"request_queue_timeout"     json:"request_queue_timeout"`
}

// BodyLimits controls request/response size thresholds.
type BodyLimits struct {
	MaxRequestBodyBytes             int64 `yaml:"max_request_body_bytes"              json:"max_request_body_bytes"`
	MaxResponseBodyBytes            int64 `yaml:"max_response_body_bytes"             json:"max_response_body_bytes"`
	StreamingParseThreshold         int64 `yaml:"streaming_parse_threshold"           json:"streaming_parse_threshold"`
	MaxResponseHeaderCount          int   `yaml:"max_response_header_count"           json:"max_response_header_count"`
	MaxResponseHeaderValueBytes     int   `yaml:"max_response_header_value_bytes"     json:"max_response_header_value_bytes"`
	MaxTotalBytesPerQuery           int64 `yaml:"max_total_bytes_per_query"           json:"max_total_bytes_per_query"`
	MaxTotalBytesPerNamespacePerMin int64 `yaml:"max_total_bytes_per_namespace_per_minute" json:"max_total_bytes_per_namespace_per_minute"`
}

// PaginationLimits controls pagination depth and row accumulation.
type PaginationLimits struct {
	MaxPagesPerRequest           int    `yaml:"max_pages_per_request"            json:"max_pages_per_request"`
	MaxRowsPerQuery              int    `yaml:"max_rows_per_query"               json:"max_rows_per_query"`
	MaxRowsInMemory              int    `yaml:"max_rows_in_memory"               json:"max_rows_in_memory"`
	PaginationInfiniteLoopWindow int    `yaml:"pagination_infinite_loop_window"  json:"pagination_infinite_loop_window"`
	MaxMergeSources              int    `yaml:"max_merge_sources"                json:"max_merge_sources"`
	MaxDeduplicateKeyCardinality int    `yaml:"max_deduplicate_key_cardinality"  json:"max_deduplicate_key_cardinality"`
	DiskSpillEnabled             bool   `yaml:"disk_spill_enabled"               json:"disk_spill_enabled"`
	DiskSpillDir                 string `yaml:"disk_spill_dir"                   json:"disk_spill_dir"`
	DiskSpillMaxBytes            int64  `yaml:"disk_spill_max_bytes"             json:"disk_spill_max_bytes"`
}

// ─── Caching ─────────────────────────────────────────────────────────────────

// CachingConfig groups request-level and response-level cache configuration.
type CachingConfig struct {
	RequestCache  RequestCacheConfig  `yaml:"request_cache"  json:"request_cache"`
	ResponseCache ResponseCacheConfig `yaml:"response_cache" json:"response_cache"`
	AdminPurgeAPI AdminPurgeAPIConfig `yaml:"admin_purge_api" json:"admin_purge_api"`
}

// RequestCacheConfig configures the HTTP-request-level deduplication cache.
// Auth and secret values are never included in cache keys or entries —
// this is a hardcoded invariant enforced in the cache.Key() function.
type RequestCacheConfig struct {
	Enabled      bool          `yaml:"enabled"       json:"enabled"`
	DefaultTTL   time.Duration `yaml:"default_ttl"   json:"default_ttl"` // 0 = no default; query must opt-in
	MaxTTL       time.Duration `yaml:"max_ttl"       json:"max_ttl"`
	MaxSizeBytes int64         `yaml:"max_size_bytes" json:"max_size_bytes"`
	MaxEntries   int           `yaml:"max_entries"   json:"max_entries"`
	DefaultScope string        `yaml:"default_scope" json:"default_scope"` // query | namespace
}

// ResponseCacheConfig configures the extracted-rows (post-EXTRACT) cache.
type ResponseCacheConfig struct {
	Enabled                bool          `yaml:"enabled"                   json:"enabled"`
	DefaultTTL             time.Duration `yaml:"default_ttl"               json:"default_ttl"`
	MaxTTL                 time.Duration `yaml:"max_ttl"                   json:"max_ttl"`
	StaleWhileRevalidateMax time.Duration `yaml:"stale_while_revalidate_max" json:"stale_while_revalidate_max"`
	MaxSizeBytes           int64         `yaml:"max_size_bytes"            json:"max_size_bytes"`
	MaxRowsPerEntry        int           `yaml:"max_rows_per_entry"        json:"max_rows_per_entry"`
	Backend                string        `yaml:"backend"                   json:"backend"` // memory | redis | memcached
	Redis                  RedisCacheConfig     `yaml:"redis"    json:"redis"`
	Memcached              MemcachedCacheConfig `yaml:"memcached" json:"memcached"`
}

// RedisCacheConfig holds Redis backend connection parameters.
type RedisCacheConfig struct {
	Address string `yaml:"address" json:"address"`
	DB      int    `yaml:"db"      json:"db"`
	TLS     bool   `yaml:"tls"     json:"tls"`
}

// MemcachedCacheConfig holds Memcached backend connection parameters.
type MemcachedCacheConfig struct {
	Addresses []string `yaml:"addresses" json:"addresses"`
}

// AdminPurgeAPIConfig controls the cache purge API endpoint.
type AdminPurgeAPIConfig struct {
	Enabled      bool `yaml:"enabled"       json:"enabled"`
	RequireToken bool `yaml:"require_token" json:"require_token"`
}

// ─── Security ────────────────────────────────────────────────────────────────

// SecurityConfig holds all security-related parameters.
type SecurityConfig struct {
	SSRFProtection    bool             `yaml:"ssrf_protection"    json:"ssrf_protection"`
	AllowedSchemes    []string         `yaml:"allowed_schemes"    json:"allowed_schemes"`
	PrivateIPDenylist PrivateIPDenylist `yaml:"private_ip_denylist" json:"private_ip_denylist"`
	PrivateIPAllowlist []string        `yaml:"private_ip_allowlist" json:"private_ip_allowlist"`
	TLS               TLSConfig        `yaml:"tls"                json:"tls"`
	Secrets           SecretsConfig    `yaml:"secrets"            json:"secrets"`
	MaxSecretRefsPerQuery int          `yaml:"max_secret_refs_per_query" json:"max_secret_refs_per_query"`
	MaxQueryPlanDepth int              `yaml:"max_query_plan_depth" json:"max_query_plan_depth"`
	AllowHTTPScheme   bool             `yaml:"allow_http_scheme"  json:"allow_http_scheme"`
}

// PrivateIPDenylist configures RFC-1918 and other private IP blocking.
type PrivateIPDenylist struct {
	Enabled        bool     `yaml:"enabled"         json:"enabled"`
	AdditionalCIDRs []string `yaml:"additional_cidrs" json:"additional_cidrs"`
}

// TLSConfig controls TLS parameters for outbound connections.
type TLSConfig struct {
	MinVersion       string `yaml:"min_version"        json:"min_version"` // TLS1.2 | TLS1.3
	VerifyCert       bool   `yaml:"verify_cert"        json:"verify_cert"`
	CustomCABundle   string `yaml:"custom_ca_bundle"   json:"custom_ca_bundle"`
	ClientCert       string `yaml:"client_cert"        json:"client_cert"`
	ClientKey        string `yaml:"client_key"         json:"client_key"`
}

// SecretsConfig controls how secrets are fetched and stored.
type SecretsConfig struct {
	MaxRefsPerQuery int    `yaml:"max_refs_per_query" json:"max_refs_per_query"`
	ValueInLogs     bool   `yaml:"value_in_logs"      json:"value_in_logs"` // hardcoded false; listed for auditability
	Backend         string `yaml:"backend"            json:"backend"` // env | vault | k8s | aws-ssm
	Vault           VaultConfig    `yaml:"vault"    json:"vault"`
	K8s             K8sConfig      `yaml:"k8s"      json:"k8s"`
	AWSSSM          AWSSMConfig    `yaml:"aws_ssm"  json:"aws_ssm"`
}

// VaultConfig configures HashiCorp Vault as the secrets backend.
type VaultConfig struct {
	Address      string `yaml:"address"         json:"address"`
	Mount        string `yaml:"mount"           json:"mount"`
	TokenEnv     string `yaml:"token_env"       json:"token_env"`
}

// K8sConfig configures Kubernetes Secrets as the secrets backend.
type K8sConfig struct {
	Namespace              string `yaml:"namespace"                 json:"namespace"`
	ServiceAccountTokenPath string `yaml:"service_account_token_path" json:"service_account_token_path"`
}

// AWSSMConfig configures AWS Systems Manager Parameter Store as secrets backend.
type AWSSMConfig struct {
	Region string `yaml:"region" json:"region"`
	Prefix string `yaml:"prefix" json:"prefix"`
}

// ─── Audit ───────────────────────────────────────────────────────────────────

// AuditConfig controls what is recorded in the audit log and where it is sent.
type AuditConfig struct {
	LogAllRequests    bool   `yaml:"log_all_requests"    json:"log_all_requests"`
	LogResponseStatus bool   `yaml:"log_response_status" json:"log_response_status"`
	LogRequestBody    bool   `yaml:"log_request_body"    json:"log_request_body"`
	LogResponseBody   bool   `yaml:"log_response_body"   json:"log_response_body"` // hardcoded false
	LogPaginationHops bool   `yaml:"log_pagination_hops" json:"log_pagination_hops"`
	LogCacheEvents    bool   `yaml:"log_cache_events"    json:"log_cache_events"`
	LogRedirectHops   bool   `yaml:"log_redirect_hops"   json:"log_redirect_hops"`
	Sink              string `yaml:"sink"                json:"sink"` // stdout | file | otlp
	File              AuditFileConfig `yaml:"file" json:"file"`
	OTLP              AuditOTLPConfig `yaml:"otlp" json:"otlp"`
	Metrics           MetricsConfig   `yaml:"metrics" json:"metrics"`
}

// AuditFileConfig configures file-based audit log output.
type AuditFileConfig struct {
	Path          string `yaml:"path"           json:"path"`
	RotateSizeMB  int    `yaml:"rotate_size_mb" json:"rotate_size_mb"`
	RotateKeep    int    `yaml:"rotate_keep"    json:"rotate_keep"`
}

// AuditOTLPConfig configures OpenTelemetry Protocol audit log export.
type AuditOTLPConfig struct {
	Endpoint string            `yaml:"endpoint" json:"endpoint"`
	Headers  map[string]string `yaml:"headers"  json:"headers"`
	TLS      bool              `yaml:"tls"      json:"tls"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	Path    string `yaml:"path"    json:"path"`
	Port    int    `yaml:"port"    json:"port"`
}

// ─── Namespace policy ────────────────────────────────────────────────────────

// Namespace defines a scoped policy override for a team, datasource, or role.
// Every field that is non-zero overrides the corresponding global admin default
// for queries running in this namespace.  Overrides can only be equal to or
// more restrictive than the global admin setting — the policy resolver enforces
// this invariant at startup.
type Namespace struct {
	Name     string         `yaml:"name"     json:"name"`
	Limits   LimitsConfig   `yaml:"limits"   json:"limits"`
	Caching  CachingConfig  `yaml:"caching"  json:"caching"`
	Security SecurityConfig `yaml:"security" json:"security"`
}
