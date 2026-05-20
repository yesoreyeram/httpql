# httpql

[![CI](https://github.com/yesoreyeram/httpql/actions/workflows/ci.yml/badge.svg)](https://github.com/yesoreyeram/httpql/actions/workflows/ci.yml)
[![Security](https://github.com/yesoreyeram/httpql/actions/workflows/security.yml/badge.svg)](https://github.com/yesoreyeram/httpql/actions/workflows/security.yml)

A safe, configurable HTTP engine for Go with its own query language. Use it to
execute outbound HTTP requests from the command line or embed the engine in your
Go application — rate limiting, timeouts, caching, SSRF protection, and audit
logging are all on by default.

---

## Table of contents

- [Installation](#installation)
- [Command-line usage](#command-line-usage)
  - [Run a query inline](#run-a-query-inline)
  - [Run a query from a file](#run-a-query-from-a-file)
  - [CLI flags](#cli-flags)
- [Query language](#query-language)
  - [Simple request](#simple-request)
  - [Request headers](#request-headers)
  - [Request body types](#request-body-types)
  - [Multiple datasources — WITH](#multiple-datasources--with)
  - [Query hints](#query-hints)
  - [Comments](#comments)
  - [Full example](#full-example)
- [Quick start (Go API)](#quick-start-go-api)
- [Making requests (Go API)](#making-requests-go-api)
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
- [Secrets](#secrets)
  - [env backend](#env-backend)
  - [vault backend](#vault-backend)
  - [k8s backend](#k8s-backend)
  - [aws-ssm backend](#aws-ssm-backend)
  - [Using secrets in Go](#using-secrets-in-go)
  - [Secret references in queries](#secret-references-in-queries)
  - [No direct environment-variable access](#no-direct-environment-variable-access)
- [TLS client certificates](#tls-client-certificates)
- [Request chaining](#request-chaining)
  - [Chaining syntax](#chaining-syntax)
  - [Response reference types](#response-reference-types)
  - [Execution order](#execution-order)
  - [Chaining in Go](#chaining-in-go)
- [Admin API](#admin-api)
- [Default limits](#default-limits)
- [Security guarantees](#security-guarantees)
- [CI / CD](#ci--cd)

---

## Installation

**Requires Go 1.25+**

Install the `httpql` CLI:

```sh
go install github.com/yesoreyeram/httpql/cmd/httpql@latest
```

Add the library to a Go module:

```sh
go get github.com/yesoreyeram/httpql
```

Build the binary from source:

```sh
git clone https://github.com/yesoreyeram/httpql
cd httpql
go build -o httpql ./cmd/httpql
./httpql version
```

---

## Command-line usage

### Run a query inline

```sh
httpql run 'GET https://api.example.com/users'
```

```sh
httpql run 'POST https://api.example.com/items BODY JSON {"name":"widget","qty":5}'
```

### Run a query from a file

Save your query in a `.httpql` file and pass the path:

```sh
httpql run query.httpql
```

### CLI flags

```
httpql run [flags] <query | file>

Flags:
  -n, --namespace string   Namespace to execute in  (default "default")
  -o, --output   string    Output format: json or text  (default "json")
      --config   string    Path to httpql-engine.yaml
                           (also read from HTTPQL_CONFIG env var)
```

**Output formats**

| `--output` | Description |
|------------|-------------|
| `json` (default) | JSON object with `status`, `headers`, `body`, `from_cache` |
| `text` | Human-readable: status line, headers, blank line, body |

**Examples**

```sh
# Pretty text output
httpql run --output text 'GET https://httpbin.org/get'

# Use a named namespace with a specific config file
httpql run --namespace analytics-team --config /etc/httpql/config.yaml query.httpql

# Start the admin server on port 9091 (default when no sub-command)
httpql
```

---

## Query language

An httpql query is a plain-text file (or string) that describes one or more HTTP
requests, plus optional hints that tune caching, concurrency, retries, and
pagination. Keywords are case-insensitive. Line comments start with `--`.

### Simple request

```
METHOD URL
```

`METHOD` is one of `GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`.

```
GET  https://api.example.com/users
POST https://api.example.com/items
```

### Request headers

Append `HEADERS` followed by a JSON object:

```
GET https://api.example.com/users
HEADERS {"Accept": "application/json", "Authorization": "Bearer token123"}
```

Multi-line JSON is fine:

```
GET https://api.example.com/users
HEADERS {
  "Accept":        "application/json",
  "Authorization": "Bearer token123"
}
```

### Request body types

Add a `BODY` clause after the URL (and after `HEADERS` if present):

| Type | Syntax | Content-Type set automatically |
|------|--------|-------------------------------|
| JSON | `BODY JSON { … }` or `BODY JSON [ … ]` | `application/json` |
| URL-encoded form | `BODY FORM key=val&key2=val2` | `application/x-www-form-urlencoded` |
| Plain text | `BODY TEXT some text here` | `text/plain; charset=utf-8` |
| Raw bytes | `BODY RAW <string data>` | `application/octet-stream` |
| GraphQL | `BODY GRAPHQL {"query":"…","variables":{…}}` | `application/json` |

> **Tip:** Add `HEADERS {"Content-Type": "application/json; version=2"}` to
> override the auto-set `Content-Type`.

**JSON body**

```
POST https://api.example.com/items
HEADERS {"Content-Type": "application/json"}
BODY JSON {"name": "widget", "qty": 5}
```

**URL-encoded form body**

```
POST https://example.com/login
BODY FORM username=alice&password=s3cr3t
```

**Plain text body**

```
POST https://example.com/log
BODY TEXT event=login user=alice
```

**GraphQL body**

```
POST https://api.example.com/graphql
BODY GRAPHQL {
  "query": "query GetUser($id: ID!) { user(id: $id) { name email } }",
  "variables": {"id": "42"}
}
```

For multi-operation documents, add `"operationName"`:

```
POST https://api.example.com/graphql
BODY GRAPHQL {
  "query": "query A { a } query B { b }",
  "operationName": "B"
}
```

### Multiple datasources — WITH

Fetch several endpoints in a single query using a `WITH` block:

```
WITH
  users  AS (GET https://api.example.com/users),
  orders AS (GET https://api.example.com/orders HEADERS {"Accept": "application/json"})
CONCURRENCY 2
```

Each datasource gets a name (the alias after `AS`).  When run with
`--output json`, the response is a JSON object keyed by those names:

```json
{
  "users":  { "status": 200, "body": [ … ] },
  "orders": { "status": 200, "body": [ … ] }
}
```

The parentheses around each request are optional when the datasource block
contains only a method and URL:

```
WITH
  a AS GET https://api.example.com/a,
  b AS GET https://api.example.com/b
```

### Query hints

Hints follow the main request or `WITH` block.  They tune the engine's guard
rail policy for this query only — the active policy caps all values at its
configured maximum, so a hint can never exceed the admin-configured limit.

| Hint | Description | Example |
|------|-------------|---------|
| `CONCURRENCY N` | Max number of parallel sub-requests | `CONCURRENCY 3` |
| `QUERY_TIMEOUT N` | Wall-clock timeout in seconds | `QUERY_TIMEOUT 30` |
| `REQUEST_CACHE N` | Cache responses for N seconds | `REQUEST_CACHE 300` |
| `CACHE N` | Enable response cache with TTL of N seconds | `CACHE 60` |
| `RETRY N` | Retry each failed request up to N times | `RETRY 2` |
| `REDIRECTS FOLLOW MAX N` | Maximum redirect hops | `REDIRECTS FOLLOW MAX 5` |
| `STOP_WHEN TOTAL_ITEMS >= N` | Stop pagination when row count reaches N | `STOP_WHEN TOTAL_ITEMS >= 1000` |
| `STOP_WHEN PAGE_COUNT >= N` | Stop pagination after N pages | `STOP_WHEN PAGE_COUNT >= 50` |

### Comments

Lines starting with `--` and inline `--` suffixes are ignored:

```
-- Fetch the user list
GET https://api.example.com/users  -- production API
CACHE 60
```

### Full example

```
-- Fetch users and orders concurrently, cache results for 5 minutes.
WITH
  users AS (
    GET https://api.example.com/users
    HEADERS {"Accept": "application/json", "Authorization": "Bearer $TOKEN"}
  ),
  orders AS (
    GET https://api.example.com/orders
    HEADERS {"Accept": "application/json"}
  )
CONCURRENCY 2
REQUEST_CACHE 300
QUERY_TIMEOUT 60
RETRY 2
STOP_WHEN TOTAL_ITEMS >= 5000
```

Save as `fetch.httpql` and run:

```sh
httpql run --namespace analytics-team --output json fetch.httpql
```

---

## Quick start (Go API)

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

## Making requests (Go API)

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

## Secrets

httpql ships with a pluggable secrets backend.  All four backends share the
same interface — `LookupSecret(ctx, key)` — so you can switch backends without
touching query files.  Secret values are **never written to any log** regardless
of which backend is active; this is a hardcoded invariant enforced in
`config.Clamp()`.

Select the backend in your config file:

```yaml
security:
  secrets:
    backend: env          # env | vault | k8s | aws-ssm
```

### env backend

Reads secrets from process environment variables.  No extra configuration is
needed.

**Key format:** exact environment-variable name (e.g. `MY_API_KEY`).

```yaml
security:
  secrets:
    backend: env
```

```go
val, err := engine.LookupSecret(ctx, "MY_API_KEY")
```

### vault backend

Reads secrets from HashiCorp Vault's **KV Secrets Engine v2** using the
Vault HTTP API.  No third-party SDK is required.

**Key format:** `{secret-path}/{field}`

The path up to the last `/` is the Vault secret path; the last segment is the
field name within the secret's data map.

**Example:** key `database/postgres/password` resolves to

```
GET {vault_address}/v1/{mount}/data/database/postgres
→ response.data.data["password"]
```

**Environment variable:** `VAULT_TOKEN` (or whatever `token_env` is set to)
must hold a valid Vault token with read access to the path.

```yaml
security:
  secrets:
    backend: vault
    vault:
      address: https://vault.internal.example.com
      mount: secret          # KV v2 mount name (default: secret)
      token_env: VAULT_TOKEN # env var that holds the Vault token
```

### k8s backend

Reads secrets from the **Kubernetes Secrets API** using the pod's service
account bearer token.  No third-party SDK is required; the implementation
uses only the standard `net/http` package.

**Key format:** `{secret-name}/{data-key}`

**Example:** key `db-credentials/password` resolves to

```
GET {k8s_api}/api/v1/namespaces/{namespace}/secrets/db-credentials
→ base64-decode(response.data["password"])
```

```yaml
security:
  secrets:
    backend: k8s
    k8s:
      namespace: production          # leave empty to use pod's own namespace
      service_account_token_path: /var/run/secrets/kubernetes.io/serviceaccount/token
```

The pod CA certificate at
`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` is used automatically
when present; otherwise the system TLS roots are used (suitable for external
clusters with a valid certificate chain).

### aws-ssm backend

Reads secrets from **AWS Systems Manager Parameter Store** (`SecureString`
parameters are decrypted automatically).  The implementation uses AWS Signature
Version 4 (SigV4) signed HTTP requests — no AWS SDK is required.

**Key format:** parameter name.  The configured `prefix` is prepended
automatically when it is not already present.

**Example:** with `prefix: /httpql/` and key `db/password`, the resolved
parameter name is `/httpql/db/password`.

| Environment variable | Required | Description |
|----------------------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | **Yes** | AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | **Yes** | AWS secret access key |
| `AWS_SESSION_TOKEN` | No | Session token for temporary credentials |
| `AWS_DEFAULT_REGION` / `AWS_REGION` | No (if set in config) | AWS region |

```yaml
security:
  secrets:
    backend: aws-ssm
    aws_ssm:
      region: us-east-1
      prefix: /httpql/     # prepended to every key automatically
```

### Using secrets in Go

```go
import (
    "context"
    "github.com/yesoreyeram/httpql/internal/secrets"
    "github.com/yesoreyeram/httpql/pkg/httpql"
)

engine, _ := httpql.New(httpql.Options{ConfigPath: "httpql-engine.yaml"})

// Resolve a secret through the configured backend.
val, err := engine.LookupSecret(context.Background(), "MY_API_KEY")
if err != nil {
    if secrets.IsNotFound(err) {
        // key does not exist in the backend
    }
    // handle transport / auth error
}
// Use val in a request header, body, etc.
```

### Secret references in queries

You can reference secrets directly in query strings using the `${secret:KEY}`
placeholder.  The engine resolves the placeholder through the configured secrets
backend at query-execution time — the secret value is never written to logs or
included in cache keys.

Placeholders are supported in:

| Location | Example |
|----------|---------|
| URL (any component) | `GET https://api.example.com/data?token=${secret:API_TOKEN}` |
| Header values | `HEADERS {"Authorization": "Bearer ${secret:API_TOKEN}"}` |
| Body (TEXT / RAW / FORM) | `BODY TEXT user=${secret:DB_USER}&pass=${secret:DB_PASS}` |

**Example — Bearer token from Vault:**

```
GET https://api.example.com/users
HEADERS {"Authorization": "Bearer ${secret:services/myapp/api_key}"}
```

**Example — Basic auth using form-encoded credentials:**

```
POST https://api.example.com/login
BODY FORM username=${secret:app/db/username}&password=${secret:app/db/password}
```

**Example — Multi-datasource WITH block with secrets:**

```
WITH
  orders AS (GET https://orders.example.com/api/orders
    HEADERS {"X-Api-Key": "${secret:orders/api_key}"}
  ),
  payments AS (GET https://payments.example.com/api/txns
    HEADERS {"Authorization": "Bearer ${secret:payments/token}"}
  )
```

The number of secret references in a query is validated against
`security.max_secret_refs_per_query` (default 5, hard maximum 20).

### No direct environment-variable access

httpql explicitly **blocks** the `${env:VAR}` placeholder.  Queries that use
`${env:...}` are rejected at parse time with a clear error message:

```
httpql: ${env:...} is not allowed in queries; use ${secret:KEY} instead
```

This is a deliberate security boundary.  All secrets must go through the
configured backend (`env`, `vault`, `k8s`, or `aws-ssm`) so that:

1. Secret access is **audited** — every lookup is logged (the value itself is
   never written, only the fact that a lookup occurred).
2. Access is **rate-limited** via `max_secret_refs_per_query`.
3. The admin can **switch backends** (from `env` to Vault, K8s, or AWS SSM)
   without touching any query files.

If you want to expose an environment variable as a secret use the `env` backend
and reference it as `${secret:MY_VAR}`.

---

## TLS client certificates

httpql supports mutual TLS (mTLS) for outbound connections.  Three TLS options
can be configured in the `security.tls` section of the config file:

| Field | Description |
|-------|-------------|
| `client_cert` | Path to a PEM-encoded client certificate file |
| `client_key` | Path to a PEM-encoded private key file (matches `client_cert`) |
| `custom_ca_bundle` | Path to a PEM-encoded CA certificate file for server verification |

`client_cert` and `client_key` must **both** be set or **both** be absent.

```yaml
security:
  tls:
    min_version: TLS1.2        # TLS1.2 | TLS1.3
    verify_cert: true          # hardcoded true in production
    custom_ca_bundle: /etc/ssl/certs/internal-ca.pem
    client_cert: /etc/ssl/certs/client.crt
    client_key:  /etc/ssl/private/client.key
```

**When `custom_ca_bundle` is set**, the CA file is used as the root of trust
for all outbound TLS connections made by the engine.  The system certificate
pool is replaced with the custom bundle, so ensure the bundle includes all
necessary intermediate and root certificates.

**When `client_cert` + `client_key` are set**, the engine presents the client
certificate for every outbound HTTPS connection.  This enables mutual TLS where
the remote server verifies the client's identity.

All TLS configuration is read at engine-startup time (not per-request) and is
fully validated before any requests are made.

---

## Request chaining

Request chaining lets you extract values from one HTTP response and pass them
to subsequent requests — in the URL, headers, or body.  This is useful for
multi-step flows like OAuth token exchange, paginated list + detail lookups, and
any workflow that depends on the output of a prior call.

### Chaining syntax

Add `${response:NAME.ACCESSOR}` placeholders in the URL, headers, or body of a
later request.  `NAME` must match the alias given to an earlier request in the
same WITH block.

```
WITH
  auth AS (POST https://auth.example.com/oauth/token
    BODY FORM grant_type=client_credentials&scope=read
  ),
  users AS (GET https://api.example.com/users
    HEADERS {"Authorization": "Bearer ${response:auth.body.access_token}"}
  )
```

### Response reference types

| Placeholder | Resolves to |
|-------------|-------------|
| `${response:NAME.body.FIELD}` | A field in the JSON response body.  Supports nested paths (`a.b.c`) and array indexing (`items[0].id`). |
| `${response:NAME.header.Header-Name}` | A response header value (case-insensitive lookup). |
| `${response:NAME.status}` | The HTTP status code as a string, e.g. `"200"`. |

**Body path examples:**

| JSON body | Placeholder | Result |
|-----------|-------------|--------|
| `{"token": "abc"}` | `${response:auth.body.token}` | `abc` |
| `{"data": {"id": 42}}` | `${response:step1.body.data.id}` | `42` |
| `{"items": [{"id": 1}, {"id": 99}]}` | `${response:list.body.items[1].id}` | `99` |

**Header example:**

```
WITH
  init AS (GET https://api.example.com/session),
  detail AS (GET https://api.example.com/resource
    HEADERS {"X-Session-Id": "${response:init.header.X-Session-Id}"}
  )
```

**Status code example:**

```
WITH
  create AS (POST https://api.example.com/items
    BODY JSON {"name": "widget"}
  ),
  audit  AS (POST https://audit.example.com/log
    BODY JSON {"event": "create", "status": "${response:create.status}"}
  )
```

**Combining secrets and response references:**

```
WITH
  token AS (POST https://auth.example.com/token
    HEADERS {"X-Client-Id": "${secret:oauth/client_id}",
             "X-Client-Secret": "${secret:oauth/client_secret}"}
  ),
  data  AS (GET https://api.example.com/data
    HEADERS {"Authorization": "${response:token.body.token_type} ${response:token.body.access_token}"}
  )
```

### Execution order

Requests in a WITH block are executed **in declaration order**.  Each request
is fully resolved (secrets and previous-response references expanded) before it
is sent.  This guarantees that any `${response:NAME...}` reference is
available by the time the referencing request runs.

If a `${response:NAME...}` placeholder refers to a request that has **not yet
run** (or does not exist), `ExecuteQuery` returns an error.

### Chaining in Go

Use `engine.ExecuteQuery` instead of `engine.ExecuteRequest` to execute a
parsed query with full chaining support:

```go
import (
    "context"
    "github.com/yesoreyeram/httpql/pkg/httpql"
)

engine, _ := httpql.New(httpql.Options{ConfigPath: "httpql-engine.yaml"})

pq, err := httpql.ParseQuery(`WITH
  auth AS (POST https://auth.example.com/token
    BODY FORM grant_type=client_credentials
  ),
  users AS (GET https://api.example.com/users
    HEADERS {"Authorization": "Bearer ${response:auth.body.access_token}"}
  )`)
if err != nil {
    // parse / validation error
}

result, err := engine.ExecuteQuery(context.Background(), "default", pq)
if err != nil {
    // execution error (secret lookup failed, network error, policy violation, etc.)
}

authResp  := result["auth"]   // *engine.Response for the auth step
usersResp := result["users"]  // *engine.Response for the users step
_ = authResp
_ = usersResp
```

`ExecuteQuery` returns a `QueryResult` (a `map[string]*engine.Response`) keyed
by the datasource name from the WITH block.  For a simple query without a WITH
block the single response is stored under the empty-string key `""`.

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

---

## CI / CD

Three GitHub Actions workflows run on every push and pull request:

| Workflow | File | Trigger | What it does |
|----------|------|---------|--------------|
| **CI** | `.github/workflows/ci.yml` | push / PR | `go vet`, `go build ./...`, `go test ./... -race` |
| **Security** | `.github/workflows/security.yml` | push / PR / weekly | `govulncheck` (known CVEs), `shadow` (variable shadowing) |
| **Release** | `.github/workflows/release.yml` | tag `v*.*.*` | Cross-compiles binaries for Linux, macOS, and Windows (amd64 + arm64), then creates a GitHub release and uploads the assets |

**Creating a release**

Push a semver tag; the release workflow handles the rest:

```sh
git tag v1.2.3
git push origin v1.2.3
```

The resulting release will include pre-built binaries for all five platforms, each named
`httpql-v1.2.3-<os>-<arch>[.exe]`.