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
	"github.com/yesoreyeram/httpql/internal/interpolate"
	"github.com/yesoreyeram/httpql/internal/policy"
	"github.com/yesoreyeram/httpql/internal/query"
	"github.com/yesoreyeram/httpql/internal/secrets"
)

// Engine is the top-level httpql engine.  Create one with New() and use it
// to execute queries with full guard rail enforcement.
type Engine struct {
	cfg            config.Config
	resolver       *policy.Resolver
	semaPool       *guardrails.SemaphorePool
	reqCache       *cache.RequestCache
	respCache      *cache.ResponseCache
	logger         *audit.Logger
	adminAPI       *admin.API
	secretProvider secrets.Provider
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

	// ── Secrets provider ──────────────────────────────────────────────────
	secretProvider, err := secrets.New(cfg.Security.Secrets)
	if err != nil {
		return nil, fmt.Errorf("httpql: initialize secrets provider: %w", err)
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
		cfg:            cfg,
		resolver:       resolver,
		semaPool:       semaPool,
		reqCache:       reqCache,
		respCache:      respCache,
		logger:         logger,
		adminAPI:       adminAPI,
		secretProvider: secretProvider,
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

// NewWithConfig creates an Engine from a pre-built [config.Config] value.
// This is useful in tests and when the caller already holds a validated config.
// opts.ConfigPath is ignored; all other Options fields apply as usual.
func NewWithConfig(cfg config.Config, opts Options) (*Engine, error) {
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

	// ── Secrets provider ──────────────────────────────────────────────────
	secretProvider, err := secrets.New(cfg.Security.Secrets)
	if err != nil {
		return nil, fmt.Errorf("httpql: initialize secrets provider: %w", err)
	}

	return &Engine{
		cfg:            cfg,
		resolver:       resolver,
		semaPool:       semaPool,
		reqCache:       reqCache,
		respCache:      respCache,
		logger:         logger,
		adminAPI:       adminAPI,
		secretProvider: secretProvider,
	}, nil
}

// ParseQuery parses an httpql query string and returns the parsed representation.
// This is a package-level convenience wrapper around [query.Parse].
func ParseQuery(src string) (*query.ParsedQuery, error) {
	return query.Parse(src)
}
//
// The key format depends on the active backend:
//
//   - env     — environment-variable name (e.g. "MY_API_KEY")
//   - vault   — "{secret-path}/{field}" (e.g. "services/myapp/api_key")
//   - k8s     — "{secret-name}/{data-key}" (e.g. "myapp-secrets/api-key")
//   - aws-ssm — parameter name; the configured prefix is prepended automatically
//
// Secret values are never written to logs regardless of the backend.
// Returns [secrets.ErrNotFound] (wrapped) when the key does not exist.
func (e *Engine) LookupSecret(ctx context.Context, key string) (string, error) {
	return e.secretProvider.Lookup(ctx, key)
}

// QueryResult holds the responses from all named requests in a parsed query.
// Keys are datasource names from the WITH block; for a simple single-request
// query the key is an empty string "".
type QueryResult map[string]*engine.Response

// ExecuteQuery validates and executes a parsed httpql query in the given
// namespace.  It handles:
//
//   - Plan-time validation against the effective policy.
//   - Secret interpolation: ${secret:KEY} placeholders in URLs, headers,
//     and body values are resolved through the configured secrets backend.
//   - Request chaining: ${response:NAME.body.PATH}, ${response:NAME.header.H},
//     and ${response:NAME.status} placeholders are resolved from prior
//     responses.  Requests are executed in declaration order so that each
//     request can reference the output of any request declared before it.
//
// The returned QueryResult maps each request's name to its [engine.Response].
// For a simple (non-WITH) query the single response is stored under the key "".
func (e *Engine) ExecuteQuery(ctx context.Context, namespace string, pq *query.ParsedQuery) (QueryResult, error) {
	ep := e.resolver.Resolve(namespace)
	pq.Plan.Namespace = namespace

	// Plan-time validation.
	result, err := guardrails.Validate(pq.Plan, ep)
	if err != nil {
		return nil, fmt.Errorf("plan validation: %w", err)
	}
	if !result.Allowed {
		return nil, fmt.Errorf("plan validation: query rejected by policy")
	}

	// Build a per-query executor.
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

	// Execute requests in declaration order, accumulating responses so that
	// later requests can reference earlier ones via ${response:NAME...}.
	responses := make(map[string]interpolate.Response, len(pq.Requests))
	out := make(QueryResult, len(pq.Requests))

	for _, nr := range pq.Requests {
		// Interpolate the request (resolve ${secret:...} and ${response:...}).
		resolved, err := e.interpolateRequest(deadlineCtx, nr.Request, responses)
		if err != nil {
			return nil, fmt.Errorf("interpolate request %q: %w", nr.Name, err)
		}

		resp, err := ex.Execute(deadlineCtx, rc, resolved)
		if err != nil {
			return nil, fmt.Errorf("execute request %q: %w", nr.Name, err)
		}

		// Store for subsequent interpolation and final output.
		responses[nr.Name] = interpolate.Response{
			StatusCode: resp.StatusCode,
			Headers:    resp.Headers,
			Body:       resp.Body,
		}
		out[nr.Name] = resp
	}

	return out, nil
}

// interpolateRequest returns a copy of req with all ${...} placeholders
// expanded using the configured secrets backend and any accumulated responses.
func (e *Engine) interpolateRequest(ctx context.Context, req engine.Request, responses map[string]interpolate.Response) (engine.Request, error) {
	sp := e.secretProvider

	expandStr := func(s string) (string, error) {
		return interpolate.Expand(ctx, s, sp, responses)
	}

	// URL
	u, err := expandStr(req.URL)
	if err != nil {
		return req, fmt.Errorf("URL: %w", err)
	}
	req.URL = u

	// Headers
	if len(req.Headers) > 0 {
		expanded := make(map[string]string, len(req.Headers))
		for k, v := range req.Headers {
			ev, err := expandStr(v)
			if err != nil {
				return req, fmt.Errorf("header %q: %w", k, err)
			}
			expanded[k] = ev
		}
		req.Headers = expanded
	}

	// Raw Body bytes (non-provider path).
	if len(req.Body) > 0 {
		eb, err := expandStr(string(req.Body))
		if err != nil {
			return req, fmt.Errorf("body: %w", err)
		}
		req.Body = []byte(eb)
	}

	return req, nil
}
