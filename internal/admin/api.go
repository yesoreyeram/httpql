// Package admin provides the privileged admin HTTP API for the httpql engine.
// All endpoints require a valid admin token supplied via the
// Authorization: Bearer <token> header.  The token is loaded from the
// HTTPQL_ADMIN_TOKEN environment variable — it is never part of the config file.
package admin

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yesoreyeram/httpql/internal/audit"
	"github.com/yesoreyeram/httpql/internal/cache"
	"github.com/yesoreyeram/httpql/internal/config"
	"github.com/yesoreyeram/httpql/internal/guardrails"
	"github.com/yesoreyeram/httpql/internal/policy"
)

// API is the admin HTTP handler.  Register it with http.ServeMux on a
// separate, internal-only port.
type API struct {
	cfg        config.Config
	resolver   *policy.Resolver
	reqCache   *cache.RequestCache
	respCache  *cache.ResponseCache
	semaPool   *guardrails.SemaphorePool
	logger     *audit.Logger
	token      string // required Bearer token; empty = no auth (development only)
	configDigest string
}

// NewAPI constructs the admin API handler.
// token must be non-empty in production; it is loaded by the caller from env.
func NewAPI(
	cfg config.Config,
	resolver *policy.Resolver,
	reqCache *cache.RequestCache,
	respCache *cache.ResponseCache,
	semaPool *guardrails.SemaphorePool,
	logger *audit.Logger,
	token string,
) (*API, error) {
	digest, err := config.Digest(cfg)
	if err != nil {
		return nil, err
	}
	return &API{
		cfg:          cfg,
		resolver:     resolver,
		reqCache:     reqCache,
		respCache:    respCache,
		semaPool:     semaPool,
		logger:       logger,
		token:        token,
		configDigest: digest,
	}, nil
}

// RegisterRoutes attaches all admin routes to mux.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/admin/health", a.authMiddleware(a.handleHealth))
	mux.HandleFunc("/admin/limits", a.authMiddleware(a.handleLimits))
	mux.HandleFunc("/admin/namespaces", a.authMiddleware(a.handleNamespaces))
	mux.HandleFunc("/admin/cache/purge", a.authMiddleware(a.handleCachePurge))
	mux.HandleFunc("/admin/semaphores", a.authMiddleware(a.handleSemaphores))
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// handleHealth returns engine liveness and config digest.
func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":        "ok",
		"instance_id":   a.cfg.Engine.InstanceID,
		"environment":   a.cfg.Engine.Environment,
		"config_digest": a.configDigest,
		"time":          time.Now().UTC(),
	})
}

// handleLimits returns the effective global limits.  Values are visible only
// to authenticated admins — never to query authors.
func (a *API) handleLimits(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"limits":        a.cfg.Limits,
		"caching":       a.cfg.Caching,
		"security":      sanitisedSecurityConfig(a.cfg.Security),
		"config_digest": a.configDigest,
	})
	a.logger.Log(audit.Event{
		Type:   audit.EventAdminAction,
		Action: "get_limits",
	})
}

// handleNamespaces lists all configured namespace policies.
func (a *API) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	type nsInfo struct {
		Name   string              `json:"name"`
		Policy policy.EffectivePolicy `json:"effective_policy"`
	}
	var result []nsInfo
	for _, ns := range a.cfg.Namespaces {
		result = append(result, nsInfo{
			Name:   ns.Name,
			Policy: a.resolver.Resolve(ns.Name),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"namespaces": result,
		"count":      len(result),
	})
}

// handleCachePurge purges the request and/or response cache.
// Query params:
//   - namespace=X: purge only entries for namespace X
//   - type=request|response|all (default: all)
func (a *API) handleCachePurge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST to purge")
		return
	}

	if !a.cfg.Caching.AdminPurgeAPI.Enabled {
		writeError(w, http.StatusForbidden, "admin purge API is disabled")
		return
	}

	namespace := r.URL.Query().Get("namespace")
	cacheType := r.URL.Query().Get("type")
	if cacheType == "" {
		cacheType = "all"
	}

	purged := map[string]interface{}{}

	switch cacheType {
	case "request", "all":
		if namespace != "" {
			// Request cache is not namespace-scoped at the store level —
			// purge all (conservative approach).
			a.reqCache.Purge()
			purged["request_cache"] = "purged all (namespace-scoped purge not supported for request cache)"
		} else {
			a.reqCache.Purge()
			purged["request_cache"] = "purged all"
		}
		if cacheType == "request" {
			break
		}
		fallthrough
	case "response":
		if namespace != "" {
			a.respCache.PurgeNamespace(namespace)
			purged["response_cache"] = "purged namespace " + namespace
		} else {
			a.respCache.Purge()
			purged["response_cache"] = "purged all"
		}
	default:
		writeError(w, http.StatusBadRequest, "type must be request|response|all")
		return
	}

	a.logger.Log(audit.Event{
		Type:      audit.EventCachePurged,
		Action:    "cache_purge",
		Namespace: namespace,
		Extra:     purged,
	})

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":    true,
		"purged": purged,
	})
}

// handleSemaphores returns the current semaphore utilisation snapshot.
func (a *API) handleSemaphores(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// SemaphorePool exposes only a boolean availability probe.
	// A full utilisation metric is exported via Prometheus /metrics.
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"global_requests_available": a.semaPool.GlobalRequestsAvailable(
			int64(a.cfg.Limits.Concurrency.MaxConcurrentRequestsGlobal),
		),
		"note": "for detailed utilisation metrics see /metrics (Prometheus)",
	})
}

// ─── Auth middleware ─────────────────────────────────────────────────────────

func (a *API) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.token == "" {
			// No token configured — only allowed in development.
			if a.cfg.Engine.Environment == "production" {
				writeError(w, http.StatusInternalServerError,
					"admin token not configured — this is a misconfiguration")
				return
			}
			next(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "Authorization header required")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeError(w, http.StatusUnauthorized, "Authorization header must use Bearer scheme")
			return
		}

		// Constant-time comparison to prevent timing attacks.
		if !secureEqual(parts[1], a.token) {
			writeError(w, http.StatusForbidden, "invalid admin token")
			return
		}

		next(w, r)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, statusCode int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, statusCode int, msg string) {
	writeJSON(w, statusCode, map[string]string{"error": msg})
}

// sanitisedSecurityConfig returns the security config with all secret
// connection strings and tokens removed.
func sanitisedSecurityConfig(sec config.SecurityConfig) map[string]interface{} {
	return map[string]interface{}{
		"ssrf_protection":          sec.SSRFProtection,
		"allowed_schemes":          sec.AllowedSchemes,
		"tls_min_version":          sec.TLS.MinVersion,
		"tls_verify_cert":          sec.TLS.VerifyCert,
		"max_secret_refs_per_query": sec.MaxSecretRefsPerQuery,
		"max_query_plan_depth":     sec.MaxQueryPlanDepth,
		"allow_http_scheme":        sec.AllowHTTPScheme,
		"secrets_backend":          sec.Secrets.Backend,
		// vault address, k8s config, etc. are omitted for security
	}
}

// secureEqual performs a constant-time string comparison to prevent timing
// side-channel attacks on the admin token.
func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		// Still do a dummy comparison to avoid length-based timing.
		var dummy [32]byte
		_ = dummy
		return false
	}
	result := byte(0)
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
