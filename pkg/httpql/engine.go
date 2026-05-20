// Package httpql is the public API surface for the httpql engine.
// All configuration, guard rail enforcement, caching, and audit logging
// are wired together here.
package httpql

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/yesoreyeram/httpql/internal/admin"
	"github.com/yesoreyeram/httpql/internal/audit"
	"github.com/yesoreyeram/httpql/internal/cache"
	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/engine"
	"github.com/yesoreyeram/httpql/internal/guardrails"
	"github.com/yesoreyeram/httpql/internal/policy"
)

// Engine is the top-level httpql engine.  Create one with New() and use it
// to execute queries with full guard rail enforcement.
type Engine struct {
	cfg       config.Config
	resolver  *policy.Resolver
	semaPool  *guardrails.SemaphorePool
	reqCache  *cache.RequestCache
	respCache *cache.ResponseCache
	logger    *audit.Logger
	adminAPI  *admin.API
}

// Options configures the Engine at creation time.
type Options struct {
	// ConfigPath is the path to the httpql-engine.yaml file.
	// If empty, all default (most-restrictive) values are used.
	ConfigPath string
	// HMACKeyHex is the hex-encoded HMAC key for config file signature
	// verification.  If non-empty, a valid .sig file must exist.
	HMACKeyHex string
	// AdminToken is the Bearer token required for all /admin/* endpoints.
	// If empty, it is read from the HTTPQL_ADMIN_TOKEN environment variable.
	AdminToken string
	// AuditOutput is the writer for audit log events.  Defaults to os.Stdout.
	AuditOutput io.Writer
}

// New creates a fully initialised Engine.  It loads and validates the config,
// initialises all guard rail enforcement structures, and starts the audit log.
func New(opts Options) (*Engine, error) {
	// ── Load config ───────────────────────────────────────────────────────
	var cfg config.Config
	var err error
	if opts.ConfigPath != "" {
		cfg, err = config.LoadFile(opts.ConfigPath, opts.HMACKeyHex)
		if err != nil {
			return nil, fmt.Errorf("httpql: load config: %w", err)
		}
	} else {
		cfg = config.Default()
	}

	// ── Resolve admin token ───────────────────────────────────────────────
	token := opts.AdminToken
	if token == "" {
		token = os.Getenv("HTTPQL_ADMIN_TOKEN")
	}
	if token == "" && cfg.Engine.Environment == "production" {
		return nil, fmt.Errorf("httpql: HTTPQL_ADMIN_TOKEN must be set in production")
	}

	// ── Set up audit logger ───────────────────────────────────────────────
	auditOut := opts.AuditOutput
	if auditOut == nil {
		auditOut = os.Stdout
	}
	logger := audit.NewLogger(auditOut, cfg.Engine.InstanceID, cfg.Audit.LogRequestBody)

	// ── Build all guard rail structures ───────────────────────────────────
	c := cfg.Limits.Concurrency
	semaPool := guardrails.NewSemaphorePool(guardrails.SemaphorePoolConfig{
		GlobalRequestsMax:        int64(c.MaxConcurrentRequestsGlobal),
		GlobalQueriesMax:         int64(c.MaxConcurrentQueriesGlobal),
		DefaultNSQueriesMax:      int64(c.MaxConcurrentQueriesPerNamespace),
		DefaultQueryRequestsMax:  int64(c.MaxConcurrentRequestsPerQuery),
		DefaultOriginRequestsMax: int64(c.MaxConcurrentRequestsPerOrigin),
	})

	rc2 := cfg.Caching.RequestCache
	reqCache := cache.NewRequestCache(rc2.MaxEntries, rc2.MaxSizeBytes)

	rsc := cfg.Caching.ResponseCache
	respCache := cache.NewResponseCache(0, rsc.MaxSizeBytes, rsc.MaxRowsPerEntry)

	resolver := policy.NewResolver(cfg)

	// ── Admin API ─────────────────────────────────────────────────────────
	adminAPI, err := admin.NewAPI(cfg, resolver, reqCache, respCache, semaPool, logger, token)
	if err != nil {
		return nil, fmt.Errorf("httpql: create admin API: %w", err)
	}

	// ── Emit engine.started audit event ──────────────────────────────────
	digest, _ := config.Digest(cfg)
	logger.Log(audit.Event{
		Type:   audit.EventEngineStarted,
		Extra: map[string]interface{}{
			"schema_version": cfg.SchemaVersion,
			"environment":    cfg.Engine.Environment,
			"limits_digest":  digest,
		},
	})

	return &Engine{
		cfg:       cfg,
		resolver:  resolver,
		semaPool:  semaPool,
		reqCache:  reqCache,
		respCache: respCache,
		logger:    logger,
		adminAPI:  adminAPI,
	}, nil
}

// ExecuteRequest executes a single HTTP sub-request for the given namespace
// with all guard rails applied.
func (e *Engine) ExecuteRequest(ctx context.Context, namespace string, req engine.Request) (*engine.Response, error) {
	ep := e.resolver.Resolve(namespace)

	// Build a per-request executor with the resolved effective policy.
	ex := engine.NewExecutor(engine.ExecutorConfig{
		EffectivePolicy: ep,
		SemaphorePool:   e.semaPool,
		RequestCache:    e.reqCache,
		ResponseCache:   e.respCache,
		Logger:          e.logger,
	})

	// Acquire query-level admission.
	releaseQuery, err := e.semaPool.AcquireQuery(ctx, namespace)
	if err != nil {
		return nil, fmt.Errorf("query admission: %w", err)
	}
	defer releaseQuery()

	// Create runtime context for this query.
	rc := guardrails.NewRuntimeContext(ep)
	deadlineCtx, cancel := rc.ContextWithDeadline(ctx)
	defer cancel()

	return ex.Execute(deadlineCtx, rc, req)
}

// ValidatePlan runs plan-time validation for a query plan in the given
// namespace.  Returns the validation result and an error if the plan is
// rejected.
func (e *Engine) ValidatePlan(namespace string, plan guardrails.QueryPlan) (guardrails.PlanValidationResult, error) {
	ep := e.resolver.Resolve(namespace)
	plan.Namespace = namespace
	return guardrails.Validate(plan, ep)
}

// RegisterAdminRoutes registers the admin HTTP API on the given mux.
func (e *Engine) RegisterAdminRoutes(mux *http.ServeMux) {
	e.adminAPI.RegisterRoutes(mux)
}

// Config returns the active configuration (read-only copy).
func (e *Engine) Config() config.Config {
	return e.cfg
}
