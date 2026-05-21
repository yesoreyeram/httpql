# Security Requirements

## SR-01 Secure Defaults
- Security-critical defaults shall be enforced in production mode.
- Clamp behavior shall prevent disabling key protections in restricted environments.

## SR-02 SSRF Protection
- Outbound requests shall be validated against SSRF restrictions before execution.

## SR-03 Secret Protection
- Secret values shall not be written to logs by default.
- Secret values shall not be exposed in cache keys.

## SR-04 Response Logging Controls
- Response body logging shall be disabled by default in secure mode.

## SR-05 TLS Verification
- Certificate verification shall be enabled by default in production.
- Any insecure TLS configuration must require explicit configuration.

## SR-06 Interpolation Safety
- `${env:...}` placeholders shall be rejected to avoid uncontrolled environment access.
- Missing or malformed interpolation references shall fail safely.

## SR-07 Credential Header Handling
- Sensitive headers (e.g., Authorization, Cookie, X-Api-Key) shall be treated as protected metadata.

## SR-08 Dependency Risk
- New dependencies shall be minimized and reviewed for known vulnerabilities.

