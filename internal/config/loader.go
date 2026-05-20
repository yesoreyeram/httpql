package config

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/yesoreyeram/httpql/internal/limits"
	"gopkg.in/yaml.v3"
)

// SupportedSchemaVersion is the only version this binary can load.
const SupportedSchemaVersion = "1.0"

// ValidationError describes a specific field that failed validation.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation error: field=%q %s", e.Field, e.Message)
}

// ValidationErrors is a multi-error carrying all validation failures found in
// one pass so the operator can fix everything at once instead of iterating.
type ValidationErrors []ValidationError

func (ve ValidationErrors) Error() string {
	msgs := make([]string, len(ve))
	for i, e := range ve {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "; ")
}

// LoadFile reads a YAML config file from disk, validates it, clamps all values
// to compiled-in hard limits, and returns the ready-to-use Config.
//
// If hmacKeyHex is non-empty, the file at path+".sig" is read and the HMAC-
// SHA256 signature is verified before any values are used.  A missing or
// invalid signature is a hard error.
func LoadFile(path, hmacKeyHex string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %q: %w", path, err)
	}

	if hmacKeyHex != "" {
		if err := verifyHMAC(data, path+".sig", hmacKeyHex); err != nil {
			return Config{}, err
		}
	}

	return Load(data)
}

// Load parses raw YAML bytes, validates, and clamps values.
// This is the entry point used by tests and by LoadFile.
func Load(data []byte) (Config, error) {
	cfg := Default()

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse YAML: %w", err)
	}

	if err := Validate(cfg); err != nil {
		return Config{}, err
	}

	Clamp(&cfg)

	return cfg, nil
}

// Validate runs all validation rules against cfg.  It collects every error
// found and returns them as a single ValidationErrors value so operators can
// fix all problems at once.
func Validate(cfg Config) error {
	var errs ValidationErrors

	// Schema version
	if cfg.SchemaVersion != SupportedSchemaVersion {
		errs = append(errs, ValidationError{
			Field:   "schema_version",
			Message: fmt.Sprintf("must be %q, got %q", SupportedSchemaVersion, cfg.SchemaVersion),
		})
	}

	// Environment
	switch cfg.Engine.Environment {
	case "production", "staging", "development":
	default:
		errs = append(errs, ValidationError{
			Field:   "engine.environment",
			Message: fmt.Sprintf("must be production|staging|development, got %q", cfg.Engine.Environment),
		})
	}

	// Production environment security invariants
	if cfg.Engine.Environment == "production" {
		if cfg.Security.AllowHTTPScheme {
			errs = append(errs, ValidationError{
				Field:   "security.allow_http_scheme",
				Message: "cannot be true in production environment",
			})
		}
		if !cfg.Security.TLS.VerifyCert {
			errs = append(errs, ValidationError{
				Field:   "security.tls.verify_cert",
				Message: "must be true in production environment",
			})
		}
		if cfg.Audit.LogResponseBody {
			errs = append(errs, ValidationError{
				Field:   "audit.log_response_body",
				Message: "response body logging is always disabled (hardcoded security invariant)",
			})
		}
		if cfg.Security.Secrets.ValueInLogs {
			errs = append(errs, ValidationError{
				Field:   "security.secrets.value_in_logs",
				Message: "secret values must never appear in logs (hardcoded security invariant)",
			})
		}
	}

	// Request cache
	if cfg.Caching.RequestCache.DefaultScope != "query" && cfg.Caching.RequestCache.DefaultScope != "namespace" {
		errs = append(errs, ValidationError{
			Field:   "caching.request_cache.default_scope",
			Message: "must be \"query\" or \"namespace\"",
		})
	}

	// Response cache backend
	switch cfg.Caching.ResponseCache.Backend {
	case "memory", "redis", "memcached":
	default:
		errs = append(errs, ValidationError{
			Field:   "caching.response_cache.backend",
			Message: fmt.Sprintf("must be memory|redis|memcached, got %q", cfg.Caching.ResponseCache.Backend),
		})
	}

	// TLS min version
	switch cfg.Security.TLS.MinVersion {
	case "TLS1.2", "TLS1.3":
	default:
		errs = append(errs, ValidationError{
			Field:   "security.tls.min_version",
			Message: fmt.Sprintf("must be TLS1.2|TLS1.3, got %q", cfg.Security.TLS.MinVersion),
		})
	}

	// Secrets backend
	switch cfg.Security.Secrets.Backend {
	case "env", "vault", "k8s", "aws-ssm":
	default:
		errs = append(errs, ValidationError{
			Field:   "security.secrets.backend",
			Message: fmt.Sprintf("must be env|vault|k8s|aws-ssm, got %q", cfg.Security.Secrets.Backend),
		})
	}

	// Positive value checks
	errs = append(errs, validatePositiveDuration("limits.timing.request_connect_timeout", cfg.Limits.Timing.RequestConnectTimeout)...)
	errs = append(errs, validatePositiveDuration("limits.timing.request_read_timeout", cfg.Limits.Timing.RequestReadTimeout)...)
	errs = append(errs, validatePositiveDuration("limits.timing.query_wall_clock_timeout", cfg.Limits.Timing.QueryWallClockTimeout)...)
	errs = append(errs, validatePositiveInt("limits.requests.max_requests_per_query", cfg.Limits.Requests.MaxRequestsPerQuery)...)
	errs = append(errs, validatePositiveInt("limits.concurrency.max_concurrent_requests_global", cfg.Limits.Concurrency.MaxConcurrentRequestsGlobal)...)
	errs = append(errs, validatePositiveInt("limits.pagination.max_pages_per_request", cfg.Limits.Pagination.MaxPagesPerRequest)...)
	errs = append(errs, validatePositiveInt("limits.pagination.max_rows_per_query", cfg.Limits.Pagination.MaxRowsPerQuery)...)

	// Namespace policies must not exceed global
	for i, ns := range cfg.Namespaces {
		prefix := fmt.Sprintf("namespaces[%d](%s)", i, ns.Name)
		if ns.Name == "" {
			errs = append(errs, ValidationError{
				Field:   prefix + ".name",
				Message: "namespace name must not be empty",
			})
		}
		errs = append(errs, validateNamespaceLimits(prefix, cfg.Limits, ns.Limits)...)
		errs = append(errs, validateNamespaceCaching(prefix, cfg.Caching, ns.Caching)...)
	}

	if len(errs) > 0 {
		return errs
	}
	return nil
}

// Clamp silently reduces any value that exceeds a compiled-in hard limit.
// It also enforces hardcoded security invariants that cannot be overridden.
func Clamp(cfg *Config) {
	r := &cfg.Limits.Requests
	r.MaxRequestsPerQuery = clampInt(r.MaxRequestsPerQuery, limits.HardMaxRequestsPerQuery)
	r.MaxDistinctOriginsPerQuery = clampInt(r.MaxDistinctOriginsPerQuery, limits.HardMaxDistinctOriginsPerQuery)
	r.MaxWithBlocksPerQuery = clampInt(r.MaxWithBlocksPerQuery, limits.HardMaxWithBlocksPerQuery)
	r.MaxRetryAttempts = clampInt(r.MaxRetryAttempts, limits.HardMaxRetryAttempts)
	r.MaxSecretRefreshesPerQuery = clampInt(r.MaxSecretRefreshesPerQuery, limits.HardMaxSecretRefreshesPerQuery)
	r.MaxRedirectsPerRequest = clampInt(r.MaxRedirectsPerRequest, limits.HardMaxRedirectsPerRequest)

	c := &cfg.Limits.Concurrency
	c.MaxConcurrentRequestsGlobal = clampInt(c.MaxConcurrentRequestsGlobal, limits.HardMaxConcurrentRequestsGlobal)
	c.MaxConcurrentRequestsPerQuery = clampInt(c.MaxConcurrentRequestsPerQuery, limits.HardMaxConcurrentRequestsPerQuery)
	c.MaxConcurrentRequestsPerOrigin = clampInt(c.MaxConcurrentRequestsPerOrigin, limits.HardMaxConcurrentRequestsPerOrigin)
	c.MaxConcurrentQueriesGlobal = clampInt(c.MaxConcurrentQueriesGlobal, limits.HardMaxConcurrentQueriesGlobal)
	c.MaxConcurrentQueriesPerNamespace = clampInt(c.MaxConcurrentQueriesPerNamespace, limits.HardMaxConcurrentQueriesPerNamespace)
	c.ConnectionPoolSizePerOrigin = clampInt(c.ConnectionPoolSizePerOrigin, limits.HardConnectionPoolSizePerOrigin)

	t := &cfg.Limits.Timing
	t.RequestConnectTimeout = clampDuration(t.RequestConnectTimeout, limits.HardRequestConnectTimeout)
	t.RequestReadTimeout = clampDuration(t.RequestReadTimeout, limits.HardRequestReadTimeout)
	t.RequestWriteTimeout = clampDuration(t.RequestWriteTimeout, limits.HardRequestWriteTimeout)
	t.QueryWallClockTimeout = clampDuration(t.QueryWallClockTimeout, limits.HardQueryWallClockTimeout)
	t.PaginationTotalTimeout = clampDuration(t.PaginationTotalTimeout, limits.HardPaginationTotalTimeout)
	t.RetryBaseDelay = clampDuration(t.RetryBaseDelay, limits.HardRetryBaseDelay)
	t.RetryMaxDelay = clampDuration(t.RetryMaxDelay, limits.HardRetryMaxDelay)
	t.RetryAfterHonourMax = clampDuration(t.RetryAfterHonourMax, limits.HardRetryAfterHonourMax)
	t.RequestQueueTimeout = clampDuration(t.RequestQueueTimeout, limits.HardRequestQueueTimeout)

	b := &cfg.Limits.Body
	b.MaxRequestBodyBytes = clampInt64(b.MaxRequestBodyBytes, limits.HardMaxRequestBodyBytes)
	b.MaxResponseBodyBytes = clampInt64(b.MaxResponseBodyBytes, limits.HardMaxResponseBodyBytes)
	b.StreamingParseThreshold = clampInt64(b.StreamingParseThreshold, limits.HardStreamingParseThreshold)
	b.MaxResponseHeaderCount = clampInt(b.MaxResponseHeaderCount, limits.HardMaxResponseHeaderCount)
	b.MaxResponseHeaderValueBytes = clampInt(b.MaxResponseHeaderValueBytes, limits.HardMaxResponseHeaderValueBytes)
	b.MaxTotalBytesPerQuery = clampInt64(b.MaxTotalBytesPerQuery, limits.HardMaxTotalBytesPerQuery)
	b.MaxTotalBytesPerNamespacePerMin = clampInt64(b.MaxTotalBytesPerNamespacePerMin, limits.HardMaxTotalBytesPerNamespacePerMin)

	p := &cfg.Limits.Pagination
	p.MaxPagesPerRequest = clampInt(p.MaxPagesPerRequest, limits.HardMaxPagesPerRequest)
	p.MaxRowsPerQuery = clampInt(p.MaxRowsPerQuery, limits.HardMaxRowsPerQuery)
	p.MaxRowsInMemory = clampInt(p.MaxRowsInMemory, limits.HardMaxRowsInMemory)
	p.PaginationInfiniteLoopWindow = clampInt(p.PaginationInfiniteLoopWindow, limits.HardPaginationInfiniteLoopWindow)
	p.MaxMergeSources = clampInt(p.MaxMergeSources, limits.HardMaxMergeSources)
	p.MaxDeduplicateKeyCardinality = clampInt(p.MaxDeduplicateKeyCardinality, limits.HardMaxDeduplicateKeyCardinality)

	rc := &cfg.Caching.RequestCache
	rc.MaxTTL = clampDuration(rc.MaxTTL, limits.HardRequestCacheMaxTTL)
	rc.MaxSizeBytes = clampInt64(rc.MaxSizeBytes, limits.HardRequestCacheMaxBytes)
	rc.MaxEntries = clampInt(rc.MaxEntries, limits.HardRequestCacheMaxEntries)

	rsp := &cfg.Caching.ResponseCache
	rsp.MaxTTL = clampDuration(rsp.MaxTTL, limits.HardResponseCacheMaxTTL)
	rsp.StaleWhileRevalidateMax = clampDuration(rsp.StaleWhileRevalidateMax, limits.HardResponseCacheSWRMax)
	rsp.MaxSizeBytes = clampInt64(rsp.MaxSizeBytes, limits.HardResponseCacheMaxBytes)
	rsp.MaxRowsPerEntry = clampInt(rsp.MaxRowsPerEntry, limits.HardResponseCacheMaxRowsPerEntry)

	sec := &cfg.Security
	sec.MaxSecretRefsPerQuery = clampInt(sec.MaxSecretRefsPerQuery, limits.HardMaxSecretRefsPerQuery)
	sec.MaxQueryPlanDepth = clampInt(sec.MaxQueryPlanDepth, limits.HardMaxQueryPlanDepth)

	// ── Hardcoded security invariants — override regardless of config ──────
	sec.SSRFProtection = true
	sec.Secrets.ValueInLogs = false
	cfg.Audit.LogResponseBody = false

	// In production, TLS verification can never be disabled.
	if cfg.Engine.Environment == "production" {
		sec.TLS.VerifyCert = true
		sec.AllowHTTPScheme = false
	}
}

// Digest returns a hex-encoded SHA-256 hash of the serialised effective limits.
// This allows operators to verify consistent configuration across replicas.
func Digest(cfg Config) (string, error) {
	data, err := json.Marshal(cfg.Limits)
	if err != nil {
		return "", fmt.Errorf("config: digest: %w", err)
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:]), nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func clampInt(v, max int) int {
	if v > max {
		return max
	}
	return v
}

func clampInt64(v, max int64) int64 {
	if v > max {
		return max
	}
	return v
}

func clampDuration(v, max time.Duration) time.Duration {
	if v > max {
		return max
	}
	return v
}

func validatePositiveInt(field string, v int) ValidationErrors {
	if v <= 0 {
		return ValidationErrors{{Field: field, Message: fmt.Sprintf("must be > 0, got %d", v)}}
	}
	return nil
}

func validatePositiveDuration(field string, v time.Duration) ValidationErrors {
	if v <= 0 {
		return ValidationErrors{{Field: field, Message: fmt.Sprintf("must be > 0, got %v", v)}}
	}
	return nil
}

func validateNamespaceLimits(prefix string, global, ns LimitsConfig) ValidationErrors {
	var errs ValidationErrors

	check := func(field string, nsVal, globalVal int) {
		if nsVal != 0 && nsVal > globalVal {
			errs = append(errs, ValidationError{
				Field:   prefix + ".limits." + field,
				Message: fmt.Sprintf("namespace value (%d) exceeds global admin value (%d)", nsVal, globalVal),
			})
		}
	}
	checkD := func(field string, nsVal, globalVal time.Duration) {
		if nsVal != 0 && nsVal > globalVal {
			errs = append(errs, ValidationError{
				Field:   prefix + ".limits." + field,
				Message: fmt.Sprintf("namespace value (%v) exceeds global admin value (%v)", nsVal, globalVal),
			})
		}
	}

	check("requests.max_requests_per_query", ns.Requests.MaxRequestsPerQuery, global.Requests.MaxRequestsPerQuery)
	check("requests.max_retry_attempts", ns.Requests.MaxRetryAttempts, global.Requests.MaxRetryAttempts)
	check("concurrency.max_concurrent_requests_per_query", ns.Concurrency.MaxConcurrentRequestsPerQuery, global.Concurrency.MaxConcurrentRequestsPerQuery)
	checkD("timing.query_wall_clock_timeout", ns.Timing.QueryWallClockTimeout, global.Timing.QueryWallClockTimeout)
	check("pagination.max_pages_per_request", ns.Pagination.MaxPagesPerRequest, global.Pagination.MaxPagesPerRequest)
	check("pagination.max_rows_per_query", ns.Pagination.MaxRowsPerQuery, global.Pagination.MaxRowsPerQuery)

	return errs
}

func validateNamespaceCaching(prefix string, global, ns CachingConfig) ValidationErrors {
	var errs ValidationErrors

	if ns.ResponseCache.MaxTTL != 0 && ns.ResponseCache.MaxTTL > global.ResponseCache.MaxTTL {
		errs = append(errs, ValidationError{
			Field:   prefix + ".caching.response_cache.max_ttl",
			Message: fmt.Sprintf("namespace cache TTL (%v) exceeds global max TTL (%v)", ns.ResponseCache.MaxTTL, global.ResponseCache.MaxTTL),
		})
	}
	return errs
}

// verifyHMAC verifies the HMAC-SHA256 signature of data against a hex-encoded
// key.  The signature is read from sigPath which must contain a single hex-
// encoded line produced by: echo -n <key_hex> | xxd -r -p | openssl dgst -sha256 -mac hmac -macopt hexkey:<key_hex> <config_file>
func verifyHMAC(data []byte, sigPath, keyHex string) error {
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("config: hmac key is not valid hex: %w", err)
	}

	sigData, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("config: read signature file %q: %w", sigPath, err)
	}

	expectedSig, err := hex.DecodeString(strings.TrimSpace(string(sigData)))
	if err != nil {
		return fmt.Errorf("config: signature file %q does not contain valid hex: %w", sigPath, err)
	}

	mac := hmac.New(sha256.New, keyBytes)
	mac.Write(data)
	actualSig := mac.Sum(nil)

	if !hmac.Equal(actualSig, expectedSig) {
		return errors.New("config: HMAC signature verification failed — config file has been tampered with or key is wrong")
	}
	return nil
}
