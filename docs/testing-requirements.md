# Testing Requirements

## TR-01 Unit Tests
- Parser behavior, interpolation logic, policy resolution, and guardrails shall have unit tests.

## TR-02 Integration Tests
- End-to-end query execution shall be covered for:
  - request chaining
  - secret interpolation
  - TLS policy application

## TR-03 Negative Tests
- Include tests for invalid query syntax, missing secrets, unresolved response refs, and policy violations.

## TR-04 Security Regression Tests
- Include tests proving `${env:...}` is rejected.
- Include tests ensuring sensitive headers are excluded from cache keys.

## TR-05 Race Detection
- Run tests with race detector enabled: `go test ./... -race`.

## TR-06 Determinism
- Tests shall avoid non-deterministic assumptions (time/network randomness).
- External calls should be mocked or use local test servers.

## TR-07 Test Data Hygiene
- Test fixtures shall not contain real secrets or credentials.

