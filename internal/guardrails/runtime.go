package guardrails

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/yesoreyeram/httpql/internal/policy"
)

// RuntimeContext tracks live resource usage for a single query execution and
// enforces runtime guard rails.  Every enforcement point in the engine calls
// into RuntimeContext before and after each operation.
//
// RuntimeContext is safe for concurrent use.
type RuntimeContext struct {
	ep policy.EffectivePolicy

	// Counters (atomic for lock-free reads in hot paths)
	requestCount  atomic.Int64
	bytesReceived atomic.Int64
	pageCount     atomic.Int64
	rowCount      atomic.Int64

	// Query deadline
	deadline time.Time

	// Pagination loop detection: ring buffer of recent cursor values.
	cursorHistory []string
	cursorPos     int
	loopWindow    int
}

// NewRuntimeContext creates a RuntimeContext that enforces ep.
// The deadline is set to now + ep.QueryWallClockTimeout.
func NewRuntimeContext(ep policy.EffectivePolicy) *RuntimeContext {
	lw := ep.PaginationInfiniteLoopWindow
	if lw <= 0 {
		lw = 5
	}
	return &RuntimeContext{
		ep:            ep,
		deadline:      time.Now().Add(ep.QueryWallClockTimeout),
		cursorHistory: make([]string, lw),
		loopWindow:    lw,
	}
}

// CheckBudgetBeforeRequest verifies that the query has not yet exhausted its
// request budget or wall-clock timeout.  Call before issuing each HTTP request.
func (rc *RuntimeContext) CheckBudgetBeforeRequest(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &PolicyError{Code: ErrQueryTimeout, Detail: "query context cancelled"}
	}
	if time.Now().After(rc.deadline) {
		return &PolicyError{Code: ErrQueryTimeout, Detail: "query wall-clock timeout exceeded"}
	}
	n := int(rc.requestCount.Add(1))
	if n > rc.ep.MaxRequestsPerQuery {
		return &PolicyError{
			Code:      ErrRequestBudget,
			Parameter: "max_requests_per_query",
			Requested: n,
			Detail:    "query request budget exhausted",
		}
	}
	return nil
}

// CheckResponseHeaders verifies header count is within limits.
// Call after receiving response headers.
func (rc *RuntimeContext) CheckResponseHeaders(headerCount int) error {
	if headerCount > rc.ep.MaxResponseHeaderCount {
		return &PolicyError{
			Code:      ErrHeaderLimitExceeded,
			Parameter: "max_response_header_count",
			Requested: headerCount,
			Detail:    "response header count exceeds configured maximum",
		}
	}
	return nil
}

// AddResponseBytes records bytes received and checks body size limits.
// Call incrementally while streaming the response body.
// Returns ErrBodyTooLarge if the per-response limit is hit.
// Returns ErrBandwidthLimit if the per-query total bandwidth limit is hit.
func (rc *RuntimeContext) AddResponseBytes(n int64, perResponseMax int64) error {
	total := rc.bytesReceived.Add(n)

	if total > perResponseMax {
		return &PolicyError{
			Code:      ErrBodyTooLarge,
			Parameter: "max_response_body_bytes",
			Requested: total,
			Detail:    "response body size exceeds configured maximum",
		}
	}
	if total > rc.ep.MaxTotalBytesPerQuery {
		return &PolicyError{
			Code:      ErrBandwidthLimit,
			Parameter: "max_total_bytes_per_query",
			Requested: total,
			Detail:    "cumulative query bandwidth limit exceeded",
		}
	}
	return nil
}

// AddPage records a pagination hop and checks pagination limits.
// Returns ErrRowsTruncated (soft limit) when the page or row ceiling is hit —
// this signals the engine to stop pagination and return partial results.
func (rc *RuntimeContext) AddPage(rowsThisPage int) error {
	pages := int(rc.pageCount.Add(1))
	rows := int(rc.rowCount.Add(int64(rowsThisPage)))

	if pages > rc.ep.MaxPagesPerRequest {
		return &PolicyError{
			Code:      ErrRowsTruncated,
			Parameter: "max_pages_per_request",
			Requested: pages,
			Detail:    "pagination page limit reached; partial results returned",
		}
	}
	if rows > rc.ep.MaxRowsPerQuery {
		return &PolicyError{
			Code:      ErrRowsTruncated,
			Parameter: "max_rows_per_query",
			Requested: rows,
			Detail:    "row limit reached; partial results returned",
		}
	}
	return nil
}

// CheckCursor detects pagination infinite loops by tracking recently seen
// cursor values.  If the same cursor appears within the loopWindow, an error
// is returned.
func (rc *RuntimeContext) CheckCursor(cursor string) error {
	// Check if cursor already seen in window.
	for _, c := range rc.cursorHistory {
		if c == cursor {
			return &PolicyError{
				Code:   ErrPaginationLoop,
				Detail: "detected repeated cursor — possible infinite pagination loop",
			}
		}
	}
	// Record cursor in ring buffer.
	rc.cursorHistory[rc.cursorPos%rc.loopWindow] = cursor
	rc.cursorPos++
	return nil
}

// Deadline returns the absolute query deadline.
func (rc *RuntimeContext) Deadline() time.Time {
	return rc.deadline
}

// RequestCount returns the number of requests issued so far.
func (rc *RuntimeContext) RequestCount() int64 {
	return rc.requestCount.Load()
}

// BytesReceived returns the total bytes received so far.
func (rc *RuntimeContext) BytesReceived() int64 {
	return rc.bytesReceived.Load()
}

// PageCount returns the total pages fetched so far.
func (rc *RuntimeContext) PageCount() int64 {
	return rc.pageCount.Load()
}

// RowCount returns the total rows accumulated so far.
func (rc *RuntimeContext) RowCount() int64 {
	return rc.rowCount.Load()
}

// ContextWithDeadline returns a copy of ctx with the query deadline applied.
// If ctx already has an earlier deadline, that earlier deadline is preserved.
func (rc *RuntimeContext) ContextWithDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithDeadline(ctx, rc.deadline)
}
