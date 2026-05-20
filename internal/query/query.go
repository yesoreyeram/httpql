// Package query implements the httpql query language parser.
//
// An httpql query describes one or more HTTP requests together with optional
// query-level hints that control concurrency, timeouts, caching, retries,
// redirects, and pagination.  The parser turns a query string into a
// [ParsedQuery] that can be validated by [guardrails.Validate] and executed
// by [httpql.Engine.ExecuteRequest].
//
// # Syntax overview
//
// Simple GET:
//
//	GET https://api.example.com/users
//
// GET with headers:
//
//	GET https://api.example.com/users
//	HEADERS {"Accept": "application/json"}
//
// POST with a JSON body:
//
//	POST https://api.example.com/items
//	HEADERS {"Content-Type": "application/json"}
//	BODY JSON {"name": "widget", "qty": 5}
//
// Multiple datasources (WITH block):
//
//	WITH
//	  users  AS (GET https://api.example.com/users),
//	  orders AS (GET https://api.example.com/orders)
//	CONCURRENCY 2
//
// Query hints follow the request or WITH block:
//
//	GET https://api.example.com/large-dataset
//	CONCURRENCY 3
//	QUERY_TIMEOUT 30
//	REQUEST_CACHE 300
//	CACHE 60
//	RETRY 2
//	REDIRECTS FOLLOW MAX 5
//	STOP_WHEN TOTAL_ITEMS >= 1000
//	STOP_WHEN PAGE_COUNT >= 50
package query

import (
	"github.com/yesoreyeram/httpql/internal/engine"
	"github.com/yesoreyeram/httpql/internal/guardrails"
)

// NamedRequest is a single HTTP source within a parsed query.
// Name is non-empty only for WITH-block datasources.
type NamedRequest struct {
	// Name is the datasource alias from the WITH … AS clause.
	// Empty for simple (non-WITH) queries.
	Name string
	// Request is the HTTP request to execute.
	Request engine.Request
}

// ParsedQuery is the complete result of parsing an httpql query string.
// It is ready for guard-rail validation via [guardrails.Validate] and for
// execution via [httpql.Engine.ExecuteRequest].
type ParsedQuery struct {
	// Plan is the static query plan used by the guardrails validator.
	Plan guardrails.QueryPlan

	// Requests is the ordered list of HTTP requests.
	// A simple query produces one entry with an empty Name.
	// A WITH query produces one entry per named datasource.
	Requests []NamedRequest
}
