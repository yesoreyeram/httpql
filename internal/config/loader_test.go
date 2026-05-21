package config_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/limits"
)

// ─── Default ─────────────────────────────────────────────────────────────────

func TestDefaultConfig_IsValid(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("Default() produced an invalid config: %v", err)
	}
}

func TestDefaultConfig_GuardRailsAreEnabled(t *testing.T) {
	t.Parallel()
	cfg := config.Default()

	// All ceilings must be positive.
	if cfg.Limits.Requests.MaxRequestsPerQuery <= 0 {
		t.Error("MaxRequestsPerQuery must be positive by default")
	}
	if cfg.Limits.Concurrency.MaxConcurrentRequestsPerQuery <= 0 {
		t.Error("MaxConcurrentRequestsPerQuery must be positive by default")
	}
	if cfg.Limits.Pagination.MaxPagesPerRequest <= 0 {
		t.Error("MaxPagesPerRequest must be positive by default")
	}

	// Security invariants must be ON.
	if !cfg.Security.SSRFProtection {
		t.Error("SSRF protection must be enabled by default")
	}
	if cfg.Security.AllowHTTPScheme {
		t.Error("HTTP scheme must be disallowed by default")
	}
	if !cfg.Security.TLS.VerifyCert {
		t.Error("TLS cert verification must be enabled by default")
	}
	if cfg.Security.Secrets.ValueInLogs {
		t.Error("secret value logging must be disabled by default")
	}

	// Response cache must be disabled by default (opt-in).
	if cfg.Caching.ResponseCache.Enabled {
		t.Error("response cache must be disabled by default")
	}

	// Request cache dedup is enabled; default TTL is 0 (no cross-query caching).
	if !cfg.Caching.RequestCache.Enabled {
		t.Error("request cache dedup must be enabled by default")
	}
	if cfg.Caching.RequestCache.DefaultTTL != 0 {
		t.Errorf("request cache default TTL must be 0 (query opt-in), got %v",
			cfg.Caching.RequestCache.DefaultTTL)
	}

	// Audit logging must be on.
	if !cfg.Audit.LogAllRequests {
		t.Error("audit.log_all_requests must be true by default")
	}
	if cfg.Audit.LogResponseBody {
		t.Error("audit.log_response_body must always be false")
	}

	// Cross-origin redirects off.
	if cfg.Limits.Requests.AllowCrossOriginRedirects {
		t.Error("cross-origin redirects must be off by default")
	}
}

// ─── Clamp ───────────────────────────────────────────────────────────────────

func TestClamp_ReducesValuesAboveHardLimits(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	// Push every value above its hard limit.
	cfg.Limits.Requests.MaxRequestsPerQuery = limits.HardMaxRequestsPerQuery * 10
	cfg.Limits.Concurrency.MaxConcurrentRequestsGlobal = limits.HardMaxConcurrentRequestsGlobal * 10
	cfg.Limits.Timing.QueryWallClockTimeout = limits.HardQueryWallClockTimeout * 10
	cfg.Limits.Body.MaxResponseBodyBytes = limits.HardMaxResponseBodyBytes * 10
	cfg.Limits.Pagination.MaxRowsPerQuery = limits.HardMaxRowsPerQuery * 10
	cfg.Caching.RequestCache.MaxTTL = limits.HardRequestCacheMaxTTL * 10
	cfg.Caching.ResponseCache.MaxTTL = limits.HardResponseCacheMaxTTL * 10
	cfg.Security.MaxQueryPlanDepth = limits.HardMaxQueryPlanDepth * 10

	config.Clamp(&cfg)

	if cfg.Limits.Requests.MaxRequestsPerQuery > limits.HardMaxRequestsPerQuery {
		t.Errorf("MaxRequestsPerQuery not clamped: %d > %d",
			cfg.Limits.Requests.MaxRequestsPerQuery, limits.HardMaxRequestsPerQuery)
	}
	if cfg.Limits.Concurrency.MaxConcurrentRequestsGlobal > limits.HardMaxConcurrentRequestsGlobal {
		t.Errorf("MaxConcurrentRequestsGlobal not clamped")
	}
	if cfg.Limits.Timing.QueryWallClockTimeout > limits.HardQueryWallClockTimeout {
		t.Errorf("QueryWallClockTimeout not clamped")
	}
	if cfg.Limits.Body.MaxResponseBodyBytes > limits.HardMaxResponseBodyBytes {
		t.Errorf("MaxResponseBodyBytes not clamped")
	}
	if cfg.Limits.Pagination.MaxRowsPerQuery > limits.HardMaxRowsPerQuery {
		t.Errorf("MaxRowsPerQuery not clamped")
	}
	if cfg.Caching.RequestCache.MaxTTL > limits.HardRequestCacheMaxTTL {
		t.Errorf("RequestCache MaxTTL not clamped")
	}
}

// TestClamp_SecurityInvariantsAreHardcoded ensures Clamp re-applies security
// invariants even if someone manually set a dangerous value.
func TestClamp_SecurityInvariantsAreHardcoded(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Engine.Environment = "production"

	// Attempt to override security invariants.
	cfg.Security.SSRFProtection = false
	cfg.Security.Secrets.ValueInLogs = true
	cfg.Audit.LogResponseBody = true
	cfg.Security.TLS.VerifyCert = false
	cfg.Security.AllowHTTPScheme = true

	config.Clamp(&cfg)

	if !cfg.Security.SSRFProtection {
		t.Error("Clamp must restore SSRFProtection=true")
	}
	if cfg.Security.Secrets.ValueInLogs {
		t.Error("Clamp must keep Secrets.ValueInLogs=false")
	}
	if cfg.Audit.LogResponseBody {
		t.Error("Clamp must keep Audit.LogResponseBody=false")
	}
	if !cfg.Security.TLS.VerifyCert {
		t.Error("Clamp must restore TLS.VerifyCert=true in production")
	}
	if cfg.Security.AllowHTTPScheme {
		t.Error("Clamp must restore AllowHTTPScheme=false in production")
	}
}

// ─── Load ────────────────────────────────────────────────────────────────────

func TestLoad_MinimalValidYAML(t *testing.T) {
	t.Parallel()

	yaml := `
schema_version: "1.0"
engine:
  environment: production
  log_level: info
`
	cfg, err := config.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if err := config.Validate(cfg); err != nil {
		t.Fatalf("loaded config is invalid: %v", err)
	}
}

func TestLoad_OverridesDefaultValues(t *testing.T) {
	t.Parallel()

	yaml := `
schema_version: "1.0"
engine:
  environment: staging
  log_level: debug
limits:
  requests:
    max_requests_per_query: 50
  timing:
    query_wall_clock_timeout: 120s
`
	cfg, err := config.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Limits.Requests.MaxRequestsPerQuery != 50 {
		t.Errorf("expected MaxRequestsPerQuery=50, got %d", cfg.Limits.Requests.MaxRequestsPerQuery)
	}
	if cfg.Limits.Timing.QueryWallClockTimeout != 120*time.Second {
		t.Errorf("expected QueryWallClockTimeout=120s, got %v", cfg.Limits.Timing.QueryWallClockTimeout)
	}
}

func TestLoad_ClampsAboveHardLimit(t *testing.T) {
	t.Parallel()

	yaml := `
schema_version: "1.0"
engine:
  environment: staging
limits:
  requests:
    max_requests_per_query: 999999
`
	cfg, err := config.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Limits.Requests.MaxRequestsPerQuery > limits.HardMaxRequestsPerQuery {
		t.Errorf("value was not clamped to hard limit %d, got %d",
			limits.HardMaxRequestsPerQuery, cfg.Limits.Requests.MaxRequestsPerQuery)
	}
}

// ─── Validate ────────────────────────────────────────────────────────────────

func TestValidate_RejectsUnknownSchemaVersion(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.SchemaVersion = "99.0"
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for unknown schema version")
	}
	if !strings.Contains(err.Error(), "schema_version") {
		t.Errorf("error should mention schema_version, got: %v", err)
	}
}

func TestValidate_RejectsHTTPInProduction(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Engine.Environment = "production"
	cfg.Security.AllowHTTPScheme = true

	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for HTTP in production")
	}
	if !strings.Contains(err.Error(), "allow_http_scheme") {
		t.Errorf("error should mention allow_http_scheme, got: %v", err)
	}
}

func TestValidate_RejectsResponseBodyLogging(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Engine.Environment = "production"
	cfg.Audit.LogResponseBody = true

	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for response body logging")
	}
	if !strings.Contains(err.Error(), "log_response_body") {
		t.Errorf("error should mention log_response_body, got: %v", err)
	}
}

func TestValidate_RejectsSecretValueInLogs(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.Engine.Environment = "production"
	cfg.Security.Secrets.ValueInLogs = true

	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for secret values in logs")
	}
	if !strings.Contains(err.Error(), "value_in_logs") {
		t.Errorf("error should mention value_in_logs, got: %v", err)
	}
}

func TestValidate_RejectsNamespaceExceedingGlobal(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	// Default max_requests_per_query = 10; try to set namespace to 100.
	cfg.Namespaces = []config.Namespace{
		{
			Name: "too-permissive",
			Limits: config.LimitsConfig{
				Requests: config.RequestLimits{
					MaxRequestsPerQuery: cfg.Limits.Requests.MaxRequestsPerQuery + 1000,
				},
			},
		},
	}

	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected validation error for namespace exceeding global limit")
	}
	if !strings.Contains(err.Error(), "max_requests_per_query") {
		t.Errorf("error should mention max_requests_per_query, got: %v", err)
	}
}

func TestValidate_CollectsMultipleErrors(t *testing.T) {
	t.Parallel()

	cfg := config.Default()
	cfg.SchemaVersion = "99.0"
	cfg.Engine.Environment = "production"
	cfg.Security.AllowHTTPScheme = true
	cfg.Audit.LogResponseBody = true

	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected multiple validation errors")
	}
	ve, ok := err.(config.ValidationErrors)
	if !ok {
		t.Fatalf("expected ValidationErrors, got %T", err)
	}
	if len(ve) < 3 {
		t.Errorf("expected at least 3 validation errors, got %d: %v", len(ve), err)
	}
}

// ─── LoadFile / HMAC ─────────────────────────────────────────────────────────

func TestLoadFile_ReturnsErrorForMissingFile(t *testing.T) {
	t.Parallel()
	_, err := config.LoadFile("/nonexistent/httpql-engine.yaml", "")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoadFile_HMACVerificationSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "httpql-engine.yaml")
	sigPath := cfgPath + ".sig"

	yamlContent := "schema_version: \"1.0\"\nengine:\n  environment: staging\n"
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	// Generate a valid HMAC.
	import_hmac_sha256(t, []byte(yamlContent), "deadbeef", sigPath)

	_, err := config.LoadFile(cfgPath, "deadbeef")
	if err != nil {
		t.Fatalf("LoadFile with valid HMAC failed: %v", err)
	}
}

func TestLoadFile_HMACVerificationFailsOnTamperedFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "httpql-engine.yaml")
	sigPath := cfgPath + ".sig"

	original := "schema_version: \"1.0\"\nengine:\n  environment: staging\n"
	tampered := original + "# extra line added by attacker\n"

	if err := os.WriteFile(cfgPath, []byte(tampered), 0600); err != nil {
		t.Fatal(err)
	}
	// Signature is for original, not tampered.
	import_hmac_sha256(t, []byte(original), "deadbeef", sigPath)

	_, err := config.LoadFile(cfgPath, "deadbeef")
	if err == nil {
		t.Fatal("expected HMAC verification failure for tampered file")
	}
	if !strings.Contains(err.Error(), "HMAC") {
		t.Errorf("error should mention HMAC, got: %v", err)
	}
}

func TestLoadFile_HMACVerificationFailsWithWrongKey(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "httpql-engine.yaml")
	sigPath := cfgPath + ".sig"

	yamlContent := "schema_version: \"1.0\"\nengine:\n  environment: staging\n"
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	import_hmac_sha256(t, []byte(yamlContent), "deadbeef", sigPath)

	_, err := config.LoadFile(cfgPath, "cafebabe") // wrong key
	if err == nil {
		t.Fatal("expected HMAC verification failure for wrong key")
	}
}

// ─── Digest ───────────────────────────────────────────────────────────────────

func TestDigest_IsDeterministic(t *testing.T) {
	t.Parallel()
	cfg := config.Default()
	d1, err := config.Digest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := config.Digest(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Error("Digest must be deterministic")
	}
}

func TestDigest_ChangesWhenLimitsChange(t *testing.T) {
	t.Parallel()
	cfg1 := config.Default()
	d1, _ := config.Digest(cfg1)

	cfg2 := config.Default()
	cfg2.Limits.Requests.MaxRequestsPerQuery = 5
	d2, _ := config.Digest(cfg2)

	if d1 == d2 {
		t.Error("Digest must change when limits change")
	}
}

// ─── test helper ─────────────────────────────────────────────────────────────

// import_hmac_sha256 writes a valid HMAC-SHA256 hex signature for data to sigPath.
func import_hmac_sha256(t *testing.T, data []byte, keyHex, sigPath string) {
	t.Helper()
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		t.Fatalf("invalid test key hex: %v", err)
	}
	mac := hmac.New(sha256.New, keyBytes)
	mac.Write(data)
	sig := hex.EncodeToString(mac.Sum(nil))
	if err := os.WriteFile(sigPath, []byte(sig), 0600); err != nil {
		t.Fatal(err)
	}
}
