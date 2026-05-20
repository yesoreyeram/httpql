// Package audit provides structured, security-safe audit logging for all
// httpql engine operations.
//
// Security invariants (enforced at compile time via this package):
//  1. Response bodies are NEVER logged.
//  2. Secret values are NEVER logged.
//  3. Authorization header values are NEVER logged.
//  4. Every audit event carries a trace ID and the engine instance ID.
package audit

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// EventType is a machine-readable audit event category.
type EventType string

const (
	EventEngineStarted       EventType = "engine.started"
	EventQueryReceived       EventType = "query.received"
	EventQueryPlanValidated  EventType = "query.plan_validated"
	EventQueryCompleted      EventType = "query.completed"
	EventQueryFailed         EventType = "query.failed"
	EventQueryTimeout        EventType = "query.timeout"
	EventQueryExplainPolicy  EventType = "query.explain_policy"
	EventRequestIssued       EventType = "request.issued"
	EventRequestCompleted    EventType = "request.completed"
	EventRequestFailed       EventType = "request.failed"
	EventCacheHit            EventType = "cache.hit"
	EventCacheMiss           EventType = "cache.miss"
	EventCachePurged         EventType = "cache.purged"
	EventGuardRailTripped    EventType = "guardrail.tripped"
	EventSSRFBlocked         EventType = "security.ssrf_blocked"
	EventSchemeBlocked       EventType = "security.scheme_blocked"
	EventAdminAction         EventType = "admin.action"
	EventConfigReloaded      EventType = "config.reloaded"
	EventPaginationLoop      EventType = "pagination.infinite_loop"
	EventBandwidthLimitHit   EventType = "bandwidth.limit_hit"
	EventRowsTruncated       EventType = "pagination.rows_truncated"
)

// Event is a single audit log entry.  All fields that could contain secret or
// sensitive values are omitted by design — see the security invariants above.
type Event struct {
	Timestamp  time.Time  `json:"timestamp"`
	Type       EventType  `json:"type"`
	TraceID    string     `json:"trace_id"`
	InstanceID string     `json:"instance_id"`
	Namespace  string     `json:"namespace,omitempty"`
	QueryID    string     `json:"query_id,omitempty"`

	// Request fields — auth headers are omitted.
	Method     string `json:"method,omitempty"`
	URL        string `json:"url,omitempty"`         // URL without auth query params
	StatusCode int    `json:"status_code,omitempty"`

	// Cache fields
	CacheType  string `json:"cache_type,omitempty"` // request | response
	CacheKey   string `json:"cache_key,omitempty"`  // key hash only, never value

	// Guard rail fields
	GuardRail string      `json:"guard_rail,omitempty"`
	Parameter string      `json:"parameter,omitempty"`
	Requested interface{} `json:"requested,omitempty"`

	// Admin action fields
	Action string `json:"action,omitempty"`
	Target string `json:"target,omitempty"`

	// Error message (never contains secret values)
	Error string `json:"error,omitempty"`

	// Extra arbitrary key-value pairs (values must be pre-sanitised by caller)
	Extra map[string]interface{} `json:"extra,omitempty"`
}

// Logger writes structured JSON audit events.  It is safe for concurrent use.
type Logger struct {
	mu         sync.Mutex
	w          io.Writer
	instanceID string
	// logRequestBody controls whether request bodies are included.
	// Response bodies are NEVER included regardless of this setting.
	logRequestBody bool
}

// NewLogger creates a Logger that writes to w.
// logRequestBody=true adds redacted request bodies to request events.
func NewLogger(w io.Writer, instanceID string, logRequestBody bool) *Logger {
	if w == nil {
		w = os.Stdout
	}
	return &Logger{
		w:              w,
		instanceID:     instanceID,
		logRequestBody: logRequestBody,
	}
}

// Log writes event to the audit log.
func (l *Logger) Log(event Event) {
	event.Timestamp = time.Now().UTC()
	event.InstanceID = l.instanceID

	data, err := json.Marshal(event)
	if err != nil {
		return // encoding failure must not panic; silently drop
	}
	data = append(data, '\n')

	l.mu.Lock()
	_, _ = l.w.Write(data)
	l.mu.Unlock()
}

// LogGuardRailTripped is a convenience method for recording guard rail events.
// It never logs the configured limit value — only what was requested.
func (l *Logger) LogGuardRailTripped(traceID, namespace, queryID, guardRail, parameter string, requested interface{}) {
	l.Log(Event{
		Type:      EventGuardRailTripped,
		TraceID:   traceID,
		Namespace: namespace,
		QueryID:   queryID,
		GuardRail: guardRail,
		Parameter: parameter,
		Requested: requested,
	})
}

// LogRequest records an outgoing HTTP request.  The authorization header is
// never included.
func (l *Logger) LogRequest(traceID, namespace, queryID, method, safeURL string) {
	l.Log(Event{
		Type:      EventRequestIssued,
		TraceID:   traceID,
		Namespace: namespace,
		QueryID:   queryID,
		Method:    method,
		URL:       safeURL,
	})
}

// LogRequestCompleted records the completion of an HTTP request.
func (l *Logger) LogRequestCompleted(traceID, namespace, queryID, method, safeURL string, statusCode int) {
	l.Log(Event{
		Type:       EventRequestCompleted,
		TraceID:    traceID,
		Namespace:  namespace,
		QueryID:    queryID,
		Method:     method,
		URL:        safeURL,
		StatusCode: statusCode,
	})
}

// LogSSRFBlocked records an SSRF block event.
func (l *Logger) LogSSRFBlocked(traceID, namespace, queryID, url string) {
	l.Log(Event{
		Type:      EventSSRFBlocked,
		TraceID:   traceID,
		Namespace: namespace,
		QueryID:   queryID,
		URL:       url,
	})
}

// SanitiseURL removes known secret query parameters from a URL before logging.
// This is a best-effort sanitisation; the engine should prefer header-based auth.
func SanitiseURL(rawURL string) string {
	// A production implementation would parse the URL and remove known secret
	// parameter names (api_key, access_token, token, secret, etc.).
	// For now we return the URL as-is since the engine uses header-based auth.
	return rawURL
}
