# Non-Functional Requirements

## NFR-01 Reliability
- Query execution shall fail fast on parse, policy, and interpolation errors.
- Execution behavior shall be deterministic for chained requests.

## NFR-02 Performance
- Overhead from parsing and interpolation shall remain bounded and predictable.
- Runtime shall avoid unnecessary allocations and repeated parsing work.

## NFR-03 Maintainability
- Architecture shall remain modular (`config`, `policy`, `guardrails`, `engine`, `query`).
- New body or secret providers shall be implementable through existing interfaces.

## NFR-04 Observability
- Logs and audit records shall be available while preventing secret leakage.
- Error messages shall be actionable and consistent.

## NFR-05 Portability
- Codebase shall compile and test with standard Go toolchain.
- External runtime dependencies shall remain minimal.

## NFR-06 Compatibility
- Public APIs should maintain backward compatibility where possible.
- Breaking changes must be explicitly versioned and documented.

