## httpql

An enterprise-grade HTTP query engine with all guard rails **on by default**.  Admins can relax limits via a signed config file; compiled-in hard limits can never be exceeded.

---

### Guard rail architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         COMPILED-IN HARD LIMITS                         │
│              (internal/limits — cannot be changed at runtime)           │
├─────────────────────────────────────────────────────────────────────────┤
│                      ADMIN CONFIG (httpql-engine.yaml)                  │
│          Default = most restrictive. Admin may relax up to hard limits. │
├─────────────────────────────────────────────────────────────────────────┤
│                        NAMESPACE POLICY OVERRIDE                        │
│    Namespace may only tighten (never exceed) the admin-level setting.   │
├─────────────────────────────────────────────────────────────────────────┤
│                           QUERY PLAN HINTS                              │
│       Query hints are clamped to effective namespace policy value.      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Guard rail families

| Family | Guard Rail | Default | Hard Limit |
|--------|-----------|---------|------------|
| **R — Requests** | Max requests per query | 10 | 500 |
| | Max distinct origins per query | 3 | 10 |
| | Max retry attempts | 3 | 10 |
| | Max redirects per request | 3 | 20 |
| | Cross-origin redirects | ❌ disabled | — |
| **C — Concurrency** | Global concurrent requests | 50 | 1 000 |
| | Per-query concurrent requests | 5 | 200 |
| | Per-origin concurrent requests | 2 | 100 |
| | Global concurrent queries | 20 | 500 |
| | Per-namespace concurrent queries | 10 | 100 |
| **T — Timing** | Request connect timeout | 5 s | 60 s |
| | Request read timeout | 30 s | 300 s |
| | Query wall-clock timeout | 60 s | 600 s |
| | Pagination total timeout | 120 s | 1 800 s |
| **B — Body** | Max response body | 10 MB | 500 MB |
| | Max total bytes per query | 100 MB | 10 GB |
| **P — Pagination** | Max pages per request | 100 | 10 000 |
| | Max rows per query | 100 000 | 10 000 000 |
| | Pagination loop window | 5 | 100 |
| **K — Caching** | Request cache | ✅ enabled (TTL=0) | — |
| | Response cache | ❌ disabled | — |
| **S — Security** | SSRF protection | ✅ always on | hardcoded |
| | HTTP scheme | ❌ blocked | hardcoded in production |
| | TLS cert verification | ✅ always on | hardcoded in production |
| | Secret values in logs | ❌ never | hardcoded |
| | Response body in logs | ❌ never | hardcoded |
| | Auth headers in cache | ❌ never cached | hardcoded |
| | Namespace cache isolation | ✅ always | hardcoded |

### Configuration

```yaml
# httpql-engine.yaml
schema_version: "1.0"

engine:
  instance_id: prod-01
  environment: production   # production | staging | development
  log_level: info

limits:
  requests:
    max_requests_per_query: 20
    max_retry_attempts: 3
    max_redirects_per_request: 3
    allow_cross_origin_redirects: false

  concurrency:
    max_concurrent_requests_global: 100
    max_concurrent_requests_per_query: 10
    max_concurrent_queries_global: 50

  timing:
    query_wall_clock_timeout: 60s
    request_read_timeout: 30s

  body:
    max_response_body_bytes: 10485760   # 10 MB

  pagination:
    max_pages_per_request: 100
    max_rows_per_query: 100000

caching:
  request_cache:
    enabled: true
    default_ttl: 0      # 0 = queries must opt-in via hint
    max_ttl: 3600s
    default_scope: query

  response_cache:
    enabled: false      # must be explicitly enabled
    backend: memory

security:
  allowed_schemes:
    - https
  tls:
    min_version: TLS1.2
    verify_cert: true
  private_ip_denylist:
    enabled: true
  secrets:
    backend: env

audit:
  log_all_requests: true
  log_response_status: true
  log_cache_events: true
  sink: stdout
  metrics:
    enabled: true
    port: 9090

namespaces:
  - name: analytics-team
    limits:
      requests:
        max_requests_per_query: 50
      pagination:
        max_rows_per_query: 500000
    caching:
      response_cache:
        enabled: true
        default_ttl: 300s
```

### Signature verification

```sh
KEY=$(openssl rand -hex 32)
openssl dgst -sha256 -mac HMAC -macopt hexkey:$KEY httpql-engine.yaml \
  | awk '{print $2}' > httpql-engine.yaml.sig

HTTPQL_CONFIG=/etc/httpql/httpql-engine.yaml \
HTTPQL_CONFIG_HMAC_KEY=$KEY \
HTTPQL_ADMIN_TOKEN=$(openssl rand -hex 32) \
httpql
```

### Project structure

```
internal/
  limits/      Compiled-in hard limit constants
  config/      Config types, defaults, loader, HMAC verification
  policy/      Policy resolver → EffectivePolicy
  guardrails/  Semaphore pool, plan-time validator, runtime context
  cache/       Request cache (auth-excluded keys), response cache
  audit/       Structured JSON audit logger
  admin/       Admin HTTP API
  engine/      HTTP executor wiring all guard rails
  sectest/     Security / penetration tests

pkg/httpql/   Public API
cmd/httpql/   Server entrypoint
```

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HTTPQL_CONFIG` | No | Path to config file |
| `HTTPQL_CONFIG_HMAC_KEY` | No | Hex HMAC key for config signature |
| `HTTPQL_ADMIN_TOKEN` | **Yes in production** | Bearer token for `/admin/*` |
| `HTTPQL_ADMIN_ADDR` | No | Admin API listen address (default `:9091`) |