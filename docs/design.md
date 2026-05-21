# HTTPQL Design Document

## 1. Purpose
This document describes the high-level design of `httpql`, a policy-aware HTTP query execution engine and language.

## 2. Goals
- Provide a query language for defining HTTP requests and request chains.
- Enforce guardrails (security, policy, limits) consistently.
- Support safe secret usage and interpolation.
- Support configurable request bodies, transport behavior, and execution controls.

## 3. Core Architecture
`httpql` is organized as layered components:
1. Hard limits layer (`internal/limits`)
2. Admin configuration layer (`internal/config`)
3. Namespace policy resolution layer (`internal/policy`)
4. Runtime enforcement and execution layer (`internal/guardrails`, `internal/engine`)

## 4. Main Components
- **Query parsing**: tokenize and parse input query text into executable structures.
- **Planning and guardrails**: validate constraints such as SSRF and request depth.
- **Execution engine**: build and execute HTTP requests with configured transport.
- **Interpolation engine**: resolve `${secret:...}` and `${response:...}` placeholders.
- **Secrets backends**: load secret values through pluggable providers.
- **Body providers**: support JSON, form, multipart, GraphQL, XML, text, and raw payloads.

## 5. Data Flow
1. Query is parsed into plan and requests.
2. Effective policy is resolved for namespace.
3. Guardrails validate requests against policy and hard limits.
4. Requests execute sequentially or as required by chain dependencies.
5. Responses are collected and used for subsequent interpolation.
6. Result is returned with request/response metadata.

## 6. Design Constraints
- Security defaults must remain enforced in production.
- Sensitive data must not leak via logs or cache keys.
- Request chaining must be deterministic and explicit.
- External dependencies should stay minimal.
