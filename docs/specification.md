# HTTPQL Specification Document

## 1. Scope
This specification defines expected behavior for query parsing, policy enforcement, interpolation, and HTTP execution in `httpql`.

## 2. Query Language
- Supports `GET`, `POST`, and other HTTP methods supported by parser/engine.
- Supports request aliases for multi-step query execution.
- Supports body methods via body providers.
- Supports headers and URL definitions per request.

## 3. Interpolation Rules
- `${secret:KEY}` resolves from configured secret backend.
- `${response:NAME.body.PATH}` resolves JSON path from prior response body.
- `${response:NAME.header.HEADER}` resolves prior response header value.
- `${response:NAME.status}` resolves prior response HTTP status code.
- `${env:...}` usage in query text is rejected.

## 4. Policy and Guardrail Enforcement
- Effective policy is derived from hard limits + admin config + namespace policy.
- Runtime checks enforce SSRF and other safety constraints.
- Security defaults are clamped in production as configured.

## 5. Transport/TLS Behavior
- TLS transport configuration supports:
  - minimum TLS version
  - certificate verification policy
  - optional custom CA bundle
  - optional client certificate/key for mTLS

## 6. Error Behavior
- Invalid syntax must fail parsing with actionable errors.
- Violations of guardrails must fail execution before outbound request.
- Missing secret or unresolved response references must fail with clear context.

