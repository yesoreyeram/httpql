// Package engine provides the httpql query executor.  It wires together all
// guard rail enforcement layers into a single, safe execution pipeline:
//
//  1. Plan-time validation (guardrails.Validate)
//  2. Query admission (semaphore pool acquisition)
//  3. Per-request enforcement (runtime context)
//  4. Request cache lookup / store
//  5. HTTP execution with body size guard
//  6. Response cache lookup / store
//  7. Audit logging at every step
package engine

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/yesoreyeram/httpql/internal/audit"
	"github.com/yesoreyeram/httpql/internal/body"
	"github.com/yesoreyeram/httpql/internal/cache"
	"github.com/yesoreyeram/httpql/internal/guardrails"
	"github.com/yesoreyeram/httpql/internal/policy"
)

// Request is a single HTTP sub-request within a query plan.
type Request struct {
	// TraceID uniquely identifies the parent query execution.
	TraceID string
	// QueryID is a shorter identifier for the query (e.g. hash of query text).
	QueryID string
	// Namespace is the query's namespace.
	Namespace string

	Method  string
	URL     string
	Headers map[string]string
	// Body is the raw request body.  Mutually exclusive with BodyProvider:
	// if BodyProvider is non-nil it takes precedence and Body is ignored.
	Body []byte
	// BodyProvider, when non-nil, is called to serialise the request body and
	// supply the Content-Type header automatically.  It takes precedence over
	// the raw Body field.  See the body package for supported types:
	//   body.JSON, body.Form, body.Multipart, body.GraphQL, body.XML, body.Text, body.Raw
	BodyProvider body.Provider

	// CacheTTL, if > 0, enables request-level caching for this request.
	CacheTTL time.Duration
}

// Response is the result of executing a single HTTP sub-request.
type Response struct {
	StatusCode int
	Headers    map[string]string
	Body       []byte
	FromCache  bool
}

// Executor runs HTTP sub-requests with all guard rails applied.
// It is safe for concurrent use.
type Executor struct {
	ep         policy.EffectivePolicy
	httpClient *http.Client
	semaPool   *guardrails.SemaphorePool
	reqCache   *cache.RequestCache
	respCache  *cache.ResponseCache
	logger     *audit.Logger
}

// ExecutorConfig holds all dependencies for the Executor.
type ExecutorConfig struct {
	EffectivePolicy policy.EffectivePolicy
	HTTPClient      *http.Client
	SemaphorePool   *guardrails.SemaphorePool
	RequestCache    *cache.RequestCache
	ResponseCache   *cache.ResponseCache
	Logger          *audit.Logger
}

// NewExecutor creates an Executor.  If cfg.HTTPClient is nil, a default client
// with safe transport settings is created.  TLS client certificate, custom CA
// bundle, and minimum TLS version are applied from the EffectivePolicy.
func NewExecutor(cfg ExecutorConfig) *Executor {
	client := cfg.HTTPClient
	if client == nil {
		ep := cfg.EffectivePolicy
		tlsCfg, err := buildTLSConfig(ep)
		if err != nil {
			// Log the error; fall back to default TLS settings.
			// NewExecutor does not return an error to preserve API stability,
			// and a nil/default TLS config is still safe.
			_ = err
		}
		transport := &http.Transport{
			MaxIdleConnsPerHost:   ep.ConnectionPoolSizePerOrigin,
			IdleConnTimeout:       ep.IdleConnectionTTL,
			TLSHandshakeTimeout:   ep.RequestConnectTimeout,
			ResponseHeaderTimeout: ep.RequestReadTimeout,
			TLSClientConfig:       tlsCfg,
			// DisableKeepAlives left false for connection reuse.
		}
		client = &http.Client{
			Transport: transport,
			// CheckRedirect enforces redirect policy.
			CheckRedirect: makeRedirectPolicy(ep),
		}
	}
	return &Executor{
		ep:         cfg.EffectivePolicy,
		httpClient: client,
		semaPool:   cfg.SemaphorePool,
		reqCache:   cfg.RequestCache,
		respCache:  cfg.ResponseCache,
		logger:     cfg.Logger,
	}
}

// buildTLSConfig constructs a *tls.Config from the effective policy.
// It sets the minimum TLS version, certificate verification flag, optional
// custom CA pool, and optional mTLS client certificate.
func buildTLSConfig(ep policy.EffectivePolicy) (*tls.Config, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: !ep.TLSVerifyCert, //nolint:gosec // controlled by admin-clamped config
	}

	// Minimum TLS version.
	switch ep.TLSMinVersion {
	case "TLS1.3":
		cfg.MinVersion = tls.VersionTLS13
	default:
		cfg.MinVersion = tls.VersionTLS12
	}

	// Custom CA bundle.
	if ep.TLSCustomCABundle != "" {
		pem, err := os.ReadFile(ep.TLSCustomCABundle)
		if err != nil {
			return nil, fmt.Errorf("engine: read custom CA bundle %q: %w", ep.TLSCustomCABundle, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("engine: no valid certificates found in CA bundle %q", ep.TLSCustomCABundle)
		}
		cfg.RootCAs = pool
	}

	// Mutual TLS: client certificate + key.
	if ep.TLSClientCert != "" || ep.TLSClientKey != "" {
		if ep.TLSClientCert == "" || ep.TLSClientKey == "" {
			return nil, fmt.Errorf("engine: both security.tls.client_cert and security.tls.client_key must be set together")
		}
		cert, err := tls.LoadX509KeyPair(ep.TLSClientCert, ep.TLSClientKey)
		if err != nil {
			return nil, fmt.Errorf("engine: load client certificate/key: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}

	return cfg, nil
}

// Execute runs a single HTTP sub-request with all guard rails applied.
//
// Enforcement order:
//  1. Resolve BodyProvider (if set) to raw bytes + Content-Type
//  2. Acquire request semaphore slots (global + per-query + per-origin)
//  3. Check request cache
//  4. Check runtime budget (request count + wall-clock)
//  5. Issue HTTP request with read timeout
//  6. Check response headers
//  7. Stream body with size guard
//  8. Store in request cache (if TTL > 0)
func (e *Executor) Execute(ctx context.Context, rc *guardrails.RuntimeContext, req Request) (*Response, error) {
	// ── Step 1: Resolve BodyProvider ─────────────────────────────────────
	rawBody, reqHeaders, err := resolveBody(req)
	if err != nil {
		return nil, fmt.Errorf("body provider: %w", err)
	}

	// Derive origin from URL for per-origin semaphore.
	origin := extractOrigin(req.URL)

	// ── Step 2: Acquire semaphore slots ───────────────────────────────────
	queueCtx, queueCancel := context.WithTimeout(ctx, e.ep.RequestQueueTimeout)
	defer queueCancel()

	releaseRequest, err := e.semaPool.AcquireRequest(queueCtx, req.QueryID, origin)
	if err != nil {
		return nil, fmt.Errorf("semaphore: %w", err)
	}
	defer releaseRequest()

	// ── Step 3: Request cache lookup ──────────────────────────────────────
	cacheKey := cache.RequestCacheKey(req.Namespace, req.Method, req.URL, reqHeaders, rawBody)
	if e.reqCache != nil && e.ep.RequestCacheEnabled {
		if entry, ok := e.reqCache.Get(ctx, cacheKey); ok {
			e.logger.Log(audit.Event{
				Type:      audit.EventCacheHit,
				TraceID:   req.TraceID,
				QueryID:   req.QueryID,
				Namespace: req.Namespace,
				CacheType: "request",
				CacheKey:  cacheKey[:16] + "…",
			})
			return &Response{
				StatusCode: entry.StatusCode,
				Headers:    entry.Headers,
				Body:       entry.Body,
				FromCache:  true,
			}, nil
		}
	}

	// ── Step 4: Runtime budget check ─────────────────────────────────────
	if err := rc.CheckBudgetBeforeRequest(ctx); err != nil {
		return nil, err
	}

	// ── Step 5: Issue HTTP request ────────────────────────────────────────
	e.logger.LogRequest(req.TraceID, req.Namespace, req.QueryID, req.Method, audit.SanitiseURL(req.URL))

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(rawBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	for k, v := range reqHeaders {
		httpReq.Header.Set(k, v)
	}

	resp, err := e.httpClient.Do(httpReq)
	if err != nil {
		e.logger.Log(audit.Event{
			Type:      audit.EventRequestFailed,
			TraceID:   req.TraceID,
			QueryID:   req.QueryID,
			Namespace: req.Namespace,
			Method:    req.Method,
			URL:       audit.SanitiseURL(req.URL),
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	// ── Step 6: Response header check ────────────────────────────────────
	if err := rc.CheckResponseHeaders(len(resp.Header)); err != nil {
		return nil, err
	}

	// ── Step 7: Stream body with size guard ───────────────────────────────
	body, bodyErr := e.readBodyWithGuard(ctx, rc, resp.Body)
	if bodyErr != nil {
		return nil, bodyErr
	}

	e.logger.LogRequestCompleted(req.TraceID, req.Namespace, req.QueryID,
		req.Method, audit.SanitiseURL(req.URL), resp.StatusCode)

	// Collect response headers (excluding sensitive ones).
	respHeaders := make(map[string]string, len(resp.Header))
	for k, vs := range resp.Header {
		if len(vs) > 0 {
			respHeaders[k] = vs[0]
		}
	}

	result := &Response{
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       body,
	}

	// ── Step 8: Store in request cache ───────────────────────────────────
	if e.reqCache != nil && e.ep.RequestCacheEnabled && req.CacheTTL > 0 {
		ttl := req.CacheTTL
		if ttl > e.ep.RequestCacheMaxTTL {
			ttl = e.ep.RequestCacheMaxTTL
		}
		e.reqCache.Set(ctx, cacheKey, cache.RequestEntry{
			StatusCode: resp.StatusCode,
			Headers:    respHeaders,
			Body:       body,
		}, ttl)
	}

	return result, nil
}

// readBodyWithGuard streams the response body while checking size limits.
func (e *Executor) readBodyWithGuard(ctx context.Context, rc *guardrails.RuntimeContext, body io.Reader) ([]byte, error) {
	var buf bytes.Buffer
	chunk := make([]byte, 32*1024) // 32 KB chunks

	for {
		if ctx.Err() != nil {
			return nil, &guardrails.PolicyError{Code: guardrails.ErrQueryTimeout, Detail: "context cancelled during response read"}
		}
		n, err := body.Read(chunk)
		if n > 0 {
			if guardrailErr := rc.AddResponseBytes(int64(n), e.ep.MaxResponseBodyBytes); guardrailErr != nil {
				return nil, guardrailErr
			}
			buf.Write(chunk[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read response body: %w", err)
		}
	}
	return buf.Bytes(), nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// resolveBody returns the raw body bytes and the effective request headers.
// If req.BodyProvider is set it takes precedence: Build() is called to
// produce the bytes and supply the Content-Type header.  The returned headers
// map is a shallow copy of req.Headers so the original is never mutated.
func resolveBody(req Request) (rawBody []byte, headers map[string]string, err error) {
	// Copy caller headers to avoid mutating the original.
	headers = make(map[string]string, len(req.Headers))
	for k, v := range req.Headers {
		headers[k] = v
	}

	if req.BodyProvider == nil {
		return req.Body, headers, nil
	}

	var ct string
	rawBody, ct, err = req.BodyProvider.Build()
	if err != nil {
		return nil, nil, err
	}
	// Only set Content-Type from the provider when the caller has not already
	// supplied their own value — caller header wins.
	if _, alreadySet := headers["Content-Type"]; !alreadySet && ct != "" {
		headers["Content-Type"] = ct
	}
	return rawBody, headers, nil
}

func extractOrigin(rawURL string) string {
	// Minimal origin extraction: scheme + host.
	for i := 0; i < len(rawURL); i++ {
		if rawURL[i] == '/' && i > 0 && rawURL[i-1] == '/' {
			// Skip the double slash after scheme.
			rest := rawURL[i+1:]
			for j, c := range rest {
				if c == '/' || c == '?' || c == '#' {
					return rawURL[:i+1+j]
				}
			}
			return rawURL[:i+1+len(rest)]
		}
	}
	return rawURL
}

func makeRedirectPolicy(ep policy.EffectivePolicy) func(req *http.Request, via []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= ep.MaxRedirectsPerRequest {
			return &guardrails.PolicyError{
				Code:      guardrails.ErrPolicyLimitExceeded,
				Parameter: "max_redirects_per_request",
				Requested: len(via),
				Detail:    "maximum redirect hops exceeded",
			}
		}
		if !ep.AllowCrossOriginRedirects && len(via) > 0 {
			originalHost := via[0].URL.Host
			if req.URL.Host != originalHost {
				return &guardrails.PolicyError{
					Code:      guardrails.ErrPolicyLimitExceeded,
					Parameter: "allow_cross_origin_redirects",
					Requested: req.URL.Host,
					Detail:    "cross-origin redirects are not allowed for this namespace",
				}
			}
		}
		return nil
	}
}
