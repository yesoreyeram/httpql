# httpql

A safe, configurable HTTP engine for Go. Use it to execute outbound HTTP requests — GET or POST — with automatic rate limiting, timeouts, caching, SSRF protection, and audit logging all on by default.

---

## Table of contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Making requests](#making-requests)
  - [GET request](#get-request)
  - [POST — JSON body](#post--json-body)
  - [POST — URL-encoded form](#post--url-encoded-form)
  - [POST — Multipart / file upload](#post--multipart--file-upload)
  - [POST — GraphQL](#post--graphql)
  - [POST — XML](#post--xml)
  - [POST — Plain text](#post--plain-text)
  - [POST — Raw bytes](#post--raw-bytes)
- [Request caching](#request-caching)
- [Namespaces](#namespaces)
- [Configuration file](#configuration-file)
  - [Minimal config](#minimal-config)
  - [Full config reference](#full-config-reference)
- [Signing the config file](#signing-the-config-file)
- [Environment variables](#environment-variables)
- [Admin API](#admin-api)
- [Default limits](#default-limits)
- [Security guarantees](#security-guarantees)

---

## Installation

**Requires Go 1.25+**

```sh
go get github.com/yesoreyeram/httpql
```

To build and run the standalone server:

```sh
go build ./cmd/httpql
./httpql
```

---

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/yesoreyeram/httpql/pkg/httpql"
    "github.com/yesoreyeram/httpql/internal/engine"
)

func main() {
    // Create the engine with safe defaults — no config file needed.
    eng, err := httpql.New(httpql.Options{})
    if err != nil {
        log.Fatal(err)
    }

    resp, err := eng.ExecuteRequest(context.Background(), "default", engine.Request{
        TraceID:   "trace-1",
        QueryID:   "q-1",
        Namespace: "default",
        Method:    "GET",
        URL:       "https://api.github.com/repos/yesoreyeram/httpql",
        Headers:   map[string]string{"Accept": "application/json"},
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %d\nBody: %s\n", resp.StatusCode, resp.Body)
}
```

---

## Making requests

Every request is described by an `engine.Request` value and executed through
`engine.ExecuteRequest`. The engine enforces timeouts, body-size limits, SSRF
protection, and concurrency limits automatically.

### GET request

```go
resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    TraceID:   "trace-1",
    QueryID:   "q-1",
    Namespace: "default",
    Method:    "GET",
    URL:       "https://httpbin.org/get",
    Headers:   map[string]string{"Accept": "application/json"},
})
```

### POST — JSON body

`body.JSON` marshals any Go value and sets `Content-Type: application/json`.

```go
import "github.com/yesoreyeram/httpql/internal/body"

resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method:       "POST",
    URL:          "https://api.example.com/items",
    BodyProvider: body.JSON{Value: map[string]any{"name": "widget", "qty": 5}},
})
```

### POST — URL-encoded form

`body.Form` encodes `url.Values` and sets
`Content-Type: application/x-www-form-urlencoded`.

```go
import "net/url"

resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method: "POST",
    URL:    "https://example.com/login",
    BodyProvider: body.Form{Values: url.Values{
        "username": {"alice"},
        "password": {"s3cr3t"},
    }},
})
```

### POST — Multipart / file upload

`body.Multipart` builds a `multipart/form-data` body. Text fields and file
parts can be mixed freely.

```go
resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method: "POST",
    URL:    "https://example.com/upload",
    BodyProvider: body.Multipart{Parts: []body.Part{
        {Name: "title", Data: []byte("Q3 Report")},
        {
            Name:        "file",
            Filename:    "report.pdf",
            ContentType: "application/pdf",
            Data:        pdfBytes,
        },
    }},
})
```

### POST — GraphQL

`body.GraphQL` produces the standard `{"query","variables","operationName"}`
JSON payload required by every GraphQL server.

```go
resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method: "POST",
    URL:    "https://api.example.com/graphql",
    BodyProvider: body.GraphQL{
        Query:     `query GetUser($id: ID!) { user(id: $id) { name email } }`,
        Variables: map[string]any{"id": "42"},
    },
})
```

When a query document contains multiple operations, set `OperationName` to
select which one to run:

```go
BodyProvider: body.GraphQL{
    Query:         `query A { a } query B { b }`,
    OperationName: "B",
},
```

### POST — XML

Pass a pre-built XML byte slice, or let the engine marshal a Go struct for you.

```go
// Pre-built bytes
resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method:       "POST",
    URL:          "https://soap.example.com/service",
    BodyProvider: body.XML{Data: []byte(`<Envelope><Body>…</Body></Envelope>`)},
})

// Auto-marshal a Go struct (uses encoding/xml)
type Item struct {
    XMLName xml.Name `xml:"item"`
    Name    string   `xml:"name"`
}
resp, err = eng.ExecuteRequest(ctx, "default", engine.Request{
    Method:       "POST",
    URL:          "https://api.example.com/items",
    BodyProvider: body.XML{Value: Item{Name: "widget"}},
})
```

### POST — Plain text

```go
resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method:       "POST",
    URL:          "https://example.com/log",
    BodyProvider: body.Text{Data: []byte("event=login user=alice")},
})
```

### POST — Raw bytes

Use `body.Raw` when you have already serialised the payload and just want to
supply a `Content-Type`.

```go
resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method: "POST",
    URL:    "https://example.com/binary",
    BodyProvider: body.Raw{
        ContentType: "application/octet-stream",
        Data:        []byte{0xDE, 0xAD, 0xBE, 0xEF},
    },
})
```

> **Tip:** If you set a `Content-Type` key inside `Headers`, it overrides the
> value chosen by the `BodyProvider`. This lets you add custom media-type
> parameters (e.g. `application/json; version=2`) without replacing the body
> serialisation logic.

---

## Request caching

Set `CacheTTL` on a request to have the engine return the cached response on
repeated identical calls (same URL, method, non-auth headers, and body).
Auth headers (`Authorization`, `Cookie`, `X-Api-Key`, etc.) are **never**
included in the cache key.

```go
resp, err := eng.ExecuteRequest(ctx, "default", engine.Request{
    Method:   "GET",
    URL:      "https://api.example.com/slow-data",
    CacheTTL: 5 * time.Minute,
})
```

`resp.FromCache` is `true` when the response was served from cache.

---

## Namespaces

Namespaces let different teams or workloads share one engine instance with
independent rate limits and cache settings. Pass the namespace name as the
second argument to `ExecuteRequest`:

```go
// analytics team gets its own limits defined in the config file
resp, err := eng.ExecuteRequest(ctx, "analytics-team", engine.Request{ … })
```

Namespace limits can only **tighten** the global admin defaults — they can
never grant more capacity than the global setting allows.

---

## Configuration file

The engine works with safe defaults out of the box. To loosen limits or change
timeouts, provide a YAML config file.

### Minimal config

```yaml
schema_version: "1.0"

engine:
  instance_id: my-app
  environment: production   # production | staging | development
```

Set the path via the `HTTPQL_CONFIG` environment variable (default:
`/etc/httpql/httpql-engine.yaml`).

### Full config reference

```yaml
schema_version: "1.0"

engine:
  instance_id: prod-01
  environment: production   # production | staging | development
  log_level: info

limits:
  requests:
    max_requests_per_query: 20        # default 10, hard limit 500
    max_retry_attempts: 3             # default 3,  hard limit 10
    max_redirects_per_request: 3      # default 3,  hard limit 20
    allow_cross_origin_redirects: false

  concurrency:
    max_concurrent_requests_global: 100   # default 50,  hard limit 1000
    max_concurrent_requests_per_query: 10 # default 5,   hard limit 200
    max_concurrent_queries_global: 50     # default 20,  hard limit 500

  timing:
    request_connect_timeout: 5s       # hard limit 60s
    request_read_timeout: 30s         # hard limit 300s
    query_wall_clock_timeout: 60s     # hard limit 600s

  body:
    max_response_body_bytes: 10485760     # 10 MB; hard limit 500 MB
    max_total_bytes_per_query: 104857600  # 100 MB; hard limit 10 GB

  pagination:
    max_pages_per_request: 100        # hard limit 10 000
    max_rows_per_query: 100000        # hard limit 10 000 000

caching:
  request_cache:
    enabled: true
    default_ttl: 0        # 0 = callers must opt-in with CacheTTL on each request
    max_ttl: 3600s
    default_scope: query  # query | namespace

  response_cache:
    enabled: false        # must be explicitly enabled
    backend: memory       # memory | redis | memcached

security:
  tls:
    min_version: TLS1.2   # TLS1.2 | TLS1.3
    verify_cert: true
  private_ip_denylist:
    enabled: true         # blocks requests to RFC-1918 and loopback addresses
  secrets:
    backend: env          # env | vault | k8s | aws-ssm

audit:
  log_all_requests: true
  log_response_status: true
  log_cache_events: true
  sink: stdout

# Per-namespace overrides (limits can only be tightened, not loosened)
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

---

## Signing the config file

In production you can protect the config file from tampering by signing it with
an HMAC-SHA256 key. The engine will refuse to start if the signature does not
match.

```sh
# 1. Generate a key and sign the config
KEY=$(openssl rand -hex 32)
openssl dgst -sha256 -mac HMAC -macopt hexkey:$KEY httpql-engine.yaml \
  | awk '{print $2}' > httpql-engine.yaml.sig

# 2. Start the engine with the key
HTTPQL_CONFIG=/etc/httpql/httpql-engine.yaml \
HTTPQL_CONFIG_HMAC_KEY=$KEY \
HTTPQL_ADMIN_TOKEN=$(openssl rand -hex 32) \
./httpql
```

If the HMAC key variable is not set, the `.sig` file is ignored and the config
is loaded without signature verification.

---

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HTTPQL_CONFIG` | No | Path to the YAML config file (default: `/etc/httpql/httpql-engine.yaml`) |
| `HTTPQL_CONFIG_HMAC_KEY` | No | Hex-encoded HMAC-SHA256 key for config signature verification |
| `HTTPQL_ADMIN_TOKEN` | **Yes in production** | Bearer token required for all `/admin/*` endpoints |
| `HTTPQL_ADMIN_ADDR` | No | Admin API listen address (default: `:9091`) |

---

## Admin API

The admin API runs on a separate port (`:9091` by default) and requires an
`Authorization: Bearer <token>` header on every request.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/admin/health` | GET | Engine liveness, instance ID, config digest |
| `/admin/limits` | GET | Active global limits and caching config |
| `/admin/namespaces` | GET | Effective policy for every configured namespace |
| `/admin/semaphores` | GET | Current concurrency semaphore usage |
| `/admin/cache/purge` | POST | Purge request and/or response cache |

**Cache purge examples**

```sh
# Purge everything
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:9091/admin/cache/purge

# Purge only the response cache for one namespace
curl -X POST -H "Authorization: Bearer $TOKEN" \
  "http://localhost:9091/admin/cache/purge?type=response&namespace=analytics-team"
```

---

## Default limits

| Category | Setting | Default | Hard ceiling |
|----------|---------|---------|--------------|
| Requests | Max requests per query | 10 | 500 |
| | Max distinct origins per query | 3 | 10 |
| | Max retries | 3 | 10 |
| | Max redirects | 3 | 20 |
| Concurrency | Global concurrent requests | 50 | 1 000 |
| | Per-query concurrent requests | 5 | 200 |
| | Per-origin concurrent requests | 2 | 100 |
| | Global concurrent queries | 20 | 500 |
| Timing | Connect timeout | 5 s | 60 s |
| | Read timeout | 30 s | 300 s |
| | Query wall-clock timeout | 60 s | 600 s |
| Body | Max response body | 10 MB | 500 MB |
| | Max total bytes per query | 100 MB | 10 GB |
| Pagination | Max pages per request | 100 | 10 000 |
| | Max rows per query | 100 000 | 10 000 000 |

Hard ceilings are compiled into the binary and cannot be exceeded by any config
file, regardless of environment.

---

## Security guarantees

The following properties are **hardcoded** and cannot be changed by any
configuration file or environment variable:

| Property | Value |
|----------|-------|
| SSRF protection (private IP block) | Always enabled |
| Secret values in audit logs | Never logged |
| Response bodies in audit logs | Never logged |
| Auth headers (`Authorization`, `Cookie`, `X-Api-Key`, …) in cache keys | Never included |
| Namespace cache isolation | Always enforced |
| TLS certificate verification *(production)* | Always on |
| Plain HTTP scheme *(production)* | Always blocked |