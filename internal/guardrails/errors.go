package guardrails

import "fmt"

// ErrorCode is a machine-readable identifier for a guard rail violation.
type ErrorCode string

const (
	// Plan-time errors
	ErrPolicyLimitExceeded ErrorCode = "POLICY_LIMIT_EXCEEDED"
	ErrSSRFBlocked         ErrorCode = "SSRF_BLOCKED"
	ErrSchemeNotAllowed    ErrorCode = "SCHEME_NOT_ALLOWED"
	ErrQueryTooDeep        ErrorCode = "QUERY_PLAN_TOO_DEEP"
	ErrCyclicDependency    ErrorCode = "CYCLIC_DEPENDENCY"

	// Runtime errors
	ErrConcurrencyLimit    ErrorCode = "CONCURRENCY_LIMIT_EXCEEDED"
	ErrRequestBudget       ErrorCode = "REQUEST_BUDGET_EXCEEDED"
	ErrQueryTimeout        ErrorCode = "QUERY_TIMEOUT"
	ErrBandwidthLimit      ErrorCode = "BANDWIDTH_LIMIT_EXCEEDED"
	ErrBodyTooLarge        ErrorCode = "BODY_TOO_LARGE"
	ErrHeaderLimitExceeded ErrorCode = "RESPONSE_HEADER_LIMIT_EXCEEDED"
	ErrRowsTruncated       ErrorCode = "ROWS_TRUNCATED"  // soft; partial result returned
	ErrPaginationLoop      ErrorCode = "PAGINATION_INFINITE_LOOP"
)

// PolicyError is returned by all guard rail enforcement functions.  It carries
// a machine-readable code, the parameter that was violated, and a user-safe
// message that never reveals the actual configured limit value.
type PolicyError struct {
	Code      ErrorCode
	Parameter string
	// Requested is the value the query tried to use (always included so the
	// author can adjust their query).
	Requested interface{}
	// Detail is a human-readable explanation that does NOT contain the admin-
	// configured maximum value.
	Detail    string
}

func (e *PolicyError) Error() string {
	if e.Parameter != "" {
		return fmt.Sprintf("guard rail [%s] parameter=%q requested=%v: %s",
			e.Code, e.Parameter, e.Requested, e.Detail)
	}
	return fmt.Sprintf("guard rail [%s]: %s", e.Code, e.Detail)
}

// IsSoftLimit reports whether the error represents a soft limit that produced
// a partial result rather than a hard abort.
func (e *PolicyError) IsSoftLimit() bool {
	return e.Code == ErrRowsTruncated
}
