package query

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/yesoreyeram/httpql/internal/body"
	"github.com/yesoreyeram/httpql/internal/engine"
)

// Parse parses src as an httpql query and returns the corresponding
// [ParsedQuery].  The returned value is ready for plan-time validation with
// [guardrails.Validate] and for execution with [httpql.Engine.ExecuteRequest].
//
// Parse is safe for concurrent use; each call creates an independent parser.
func Parse(src string) (*ParsedQuery, error) {
	p := &parser{s: newScanner(src)}
	return p.parseQuery()
}

// ─── internal parser ──────────────────────────────────────────────────────────

type parser struct {
	s *scanner
}

// parseQuery is the top-level rule:
//
//	query = (withClause | simpleRequest) hint*
func (p *parser) parseQuery() (*ParsedQuery, error) {
	t := p.s.peek()
	if t.kind == tokEOF {
		return nil, fmt.Errorf("httpql: empty query")
	}

	pq := &ParsedQuery{}

	switch {
	case t.kind == tokWord && strings.ToUpper(t.val) == "WITH":
		if err := p.parseWithClause(pq); err != nil {
			return nil, err
		}
	case t.kind == tokWord && isHTTPMethod(strings.ToUpper(t.val)):
		req, err := p.parseRequest()
		if err != nil {
			return nil, err
		}
		pq.Requests = append(pq.Requests, NamedRequest{Request: *req})
	default:
		return nil, fmt.Errorf("httpql: expected an HTTP method (GET, POST, …) or WITH, got %q", t.val)
	}

	// Query-level hints follow the main request or WITH block.
	if err := p.parseHints(pq); err != nil {
		return nil, err
	}

	// All input must be consumed.
	if tok := p.s.peek(); tok.kind != tokEOF {
		return nil, fmt.Errorf("httpql: unexpected token %q after query body", tok.val)
	}

	// Populate derived QueryPlan fields.
	pq.Plan.WithBlocks = len(pq.Requests)
	for _, nr := range pq.Requests {
		if nr.Request.URL != "" {
			pq.Plan.URLs = append(pq.Plan.URLs, nr.Request.URL)
		}
	}

	return pq, nil
}

// parseWithClause parses:
//
//	WITH namedRequest (',' namedRequest)*
func (p *parser) parseWithClause(pq *ParsedQuery) error {
	p.s.next() // consume WITH
	for {
		nr, err := p.parseNamedRequest()
		if err != nil {
			return err
		}
		pq.Requests = append(pq.Requests, *nr)
		if p.s.peek().kind == tokComma {
			p.s.next() // consume ','
			continue
		}
		break
	}
	return nil
}

// parseNamedRequest parses:
//
//	IDENT AS ( request ) | IDENT AS request
func (p *parser) parseNamedRequest() (*NamedRequest, error) {
	nameTok := p.s.next()
	if nameTok.kind != tokWord {
		return nil, fmt.Errorf("httpql: WITH clause: expected datasource name, got %q", nameTok.val)
	}

	asTok := p.s.next()
	if asTok.kind != tokWord || !strings.EqualFold(asTok.val, "AS") {
		return nil, fmt.Errorf("httpql: WITH clause: expected AS after %q, got %q", nameTok.val, asTok.val)
	}

	hasParen := p.s.peek().kind == tokLParen
	if hasParen {
		p.s.next() // consume '('
	}

	req, err := p.parseRequest()
	if err != nil {
		return nil, fmt.Errorf("httpql: WITH %q: %w", nameTok.val, err)
	}

	if hasParen {
		if tok := p.s.next(); tok.kind != tokRParen {
			return nil, fmt.Errorf("httpql: WITH %q: expected ) to close the request block, got %q", nameTok.val, tok.val)
		}
	}

	return &NamedRequest{Name: nameTok.val, Request: *req}, nil
}

// parseRequest parses a single HTTP request:
//
//	METHOD URL [HEADERS json] [BODY type value]
func (p *parser) parseRequest() (*engine.Request, error) {
	methodTok := p.s.next()
	if methodTok.kind != tokWord || !isHTTPMethod(strings.ToUpper(methodTok.val)) {
		return nil, fmt.Errorf("httpql: expected an HTTP method (GET, POST, PUT, PATCH, DELETE, HEAD), got %q", methodTok.val)
	}
	method := strings.ToUpper(methodTok.val)

	urlTok := p.s.next()
	if urlTok.kind != tokURL && urlTok.kind != tokWord {
		return nil, fmt.Errorf("httpql: %s: expected a URL, got %q", method, urlTok.val)
	}
	rawURL := urlTok.val
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return nil, fmt.Errorf("httpql: %s: invalid URL %q: %w", method, rawURL, err)
	}

	req := &engine.Request{Method: method, URL: rawURL}

	// Optional HEADERS and BODY clauses.
	for {
		t := p.s.peek()
		if t.kind == tokEOF || t.kind == tokComma || t.kind == tokRParen {
			break
		}
		if t.kind != tokWord {
			break
		}
		upper := strings.ToUpper(t.val)
		if isHintKeyword(upper) {
			break // hints belong to the outer query, not this request
		}
		switch upper {
		case "HEADERS":
			p.s.next()
			hdrs, err := p.parseHeadersClause()
			if err != nil {
				return nil, err
			}
			req.Headers = hdrs
		case "BODY":
			p.s.next()
			if err := p.parseBodyClause(req); err != nil {
				return nil, err
			}
		default:
			goto done
		}
	}
done:
	return req, nil
}

// parseHeadersClause parses:
//
//	HEADERS json-object
func (p *parser) parseHeadersClause() (map[string]string, error) {
	t := p.s.peek()
	if t.kind != tokJSON {
		return nil, fmt.Errorf("httpql: HEADERS: expected a JSON object { }, got %q", t.val)
	}
	p.s.next()
	var m map[string]string
	if err := json.Unmarshal([]byte(t.val), &m); err != nil {
		return nil, fmt.Errorf("httpql: HEADERS: JSON parse error: %w", err)
	}
	return m, nil
}

// parseBodyClause parses:
//
//	BODY (JSON json | FORM text | TEXT text | RAW text | GRAPHQL json)
func (p *parser) parseBodyClause(req *engine.Request) error {
	typeTok := p.s.next()
	if typeTok.kind != tokWord {
		return fmt.Errorf("httpql: BODY: expected type (JSON, FORM, TEXT, RAW, GRAPHQL), got %q", typeTok.val)
	}
	switch strings.ToUpper(typeTok.val) {

	case "JSON":
		t := p.s.next()
		if t.kind != tokJSON {
			return fmt.Errorf("httpql: BODY JSON: expected a JSON value { } or [ ], got %q", t.val)
		}
		if !json.Valid([]byte(t.val)) {
			return fmt.Errorf("httpql: BODY JSON: value is not valid JSON")
		}
		req.BodyProvider = body.JSON{Value: json.RawMessage(t.val)}

	case "FORM":
		// Read rest of line as URL-encoded key=value&... string.
		val := p.s.readLine()
		req.BodyProvider = body.Form{Values: parseFormValues(val)}

	case "TEXT":
		val := p.s.readLine()
		req.BodyProvider = body.Text{Data: []byte(val)}

	case "RAW":
		val := p.s.readLine()
		req.BodyProvider = body.Raw{Data: []byte(val)}

	case "GRAPHQL":
		t := p.s.next()
		if t.kind != tokJSON {
			return fmt.Errorf("httpql: BODY GRAPHQL: expected a JSON object, got %q", t.val)
		}
		var gql struct {
			Query         string         `json:"query"`
			Variables     map[string]any `json:"variables"`
			OperationName string         `json:"operationName"`
		}
		if err := json.Unmarshal([]byte(t.val), &gql); err != nil {
			return fmt.Errorf("httpql: BODY GRAPHQL: JSON parse error: %w", err)
		}
		if strings.TrimSpace(gql.Query) == "" {
			return fmt.Errorf("httpql: BODY GRAPHQL: requires a non-empty \"query\" field")
		}
		req.BodyProvider = body.GraphQL{
			Query:         gql.Query,
			Variables:     gql.Variables,
			OperationName: gql.OperationName,
		}

	default:
		return fmt.Errorf("httpql: BODY: unknown type %q; supported: JSON, FORM, TEXT, RAW, GRAPHQL", typeTok.val)
	}
	return nil
}

// parseHints parses zero or more query-level hints:
//
//	hint = CONCURRENCY int
//	     | QUERY_TIMEOUT int
//	     | REQUEST_CACHE int
//	     | CACHE int
//	     | RETRY int
//	     | REDIRECTS FOLLOW MAX int
//	     | STOP_WHEN TOTAL_ITEMS >= int
//	     | STOP_WHEN PAGE_COUNT >= int
func (p *parser) parseHints(pq *ParsedQuery) error {
	for {
		t := p.s.peek()
		if t.kind == tokEOF || t.kind != tokWord {
			break
		}
		if !isHintKeyword(strings.ToUpper(t.val)) {
			break
		}
		if err := p.parseOneHint(pq); err != nil {
			return err
		}
	}
	return nil
}

func (p *parser) parseOneHint(pq *ParsedQuery) error {
	t := p.s.next()
	switch strings.ToUpper(t.val) {

	case "CONCURRENCY":
		n, err := p.expectInt("CONCURRENCY")
		if err != nil {
			return err
		}
		pq.Plan.ConcurrencyHint = n

	case "QUERY_TIMEOUT":
		n, err := p.expectInt("QUERY_TIMEOUT")
		if err != nil {
			return err
		}
		pq.Plan.QueryTimeoutHint = n

	case "REQUEST_CACHE":
		n, err := p.expectInt("REQUEST_CACHE")
		if err != nil {
			return err
		}
		pq.Plan.RequestCacheTTLHint = n
		// Propagate TTL to all requests so the executor stores responses.
		for i := range pq.Requests {
			pq.Requests[i].Request.CacheTTL = time.Duration(n) * time.Second
		}

	case "CACHE":
		n, err := p.expectInt("CACHE")
		if err != nil {
			return err
		}
		pq.Plan.ResponseCacheTTLHint = n

	case "RETRY":
		n, err := p.expectInt("RETRY")
		if err != nil {
			return err
		}
		pq.Plan.RetryHint = n

	case "REDIRECTS":
		if err := p.expectKeyword("FOLLOW", "REDIRECTS"); err != nil {
			return err
		}
		if err := p.expectKeyword("MAX", "REDIRECTS FOLLOW"); err != nil {
			return err
		}
		n, err := p.expectInt("REDIRECTS FOLLOW MAX")
		if err != nil {
			return err
		}
		pq.Plan.RedirectMaxHint = n

	case "STOP_WHEN":
		what := p.s.next()
		if what.kind != tokWord {
			return fmt.Errorf("httpql: STOP_WHEN: expected TOTAL_ITEMS or PAGE_COUNT, got %q", what.val)
		}
		switch strings.ToUpper(what.val) {
		case "TOTAL_ITEMS":
			if err := p.expectGTE("STOP_WHEN TOTAL_ITEMS"); err != nil {
				return err
			}
			n, err := p.expectInt("STOP_WHEN TOTAL_ITEMS >=")
			if err != nil {
				return err
			}
			pq.Plan.MaxRowsHint = n
		case "PAGE_COUNT":
			if err := p.expectGTE("STOP_WHEN PAGE_COUNT"); err != nil {
				return err
			}
			n, err := p.expectInt("STOP_WHEN PAGE_COUNT >=")
			if err != nil {
				return err
			}
			pq.Plan.MaxPagesHint = n
		default:
			return fmt.Errorf("httpql: STOP_WHEN: expected TOTAL_ITEMS or PAGE_COUNT, got %q", what.val)
		}

	default:
		return fmt.Errorf("httpql: unknown hint %q", t.val)
	}
	return nil
}

// ─── small helpers ────────────────────────────────────────────────────────────

func (p *parser) expectInt(context string) (int, error) {
	t := p.s.next()
	if t.kind != tokInt {
		return 0, fmt.Errorf("httpql: %s: expected an integer, got %q", context, t.val)
	}
	n, err := strconv.Atoi(t.val)
	if err != nil {
		return 0, fmt.Errorf("httpql: %s: %w", context, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("httpql: %s: value must be non-negative", context)
	}
	return n, nil
}

func (p *parser) expectKeyword(kw, context string) error {
	t := p.s.next()
	if t.kind != tokWord || !strings.EqualFold(t.val, kw) {
		return fmt.Errorf("httpql: %s: expected %q, got %q", context, kw, t.val)
	}
	return nil
}

func (p *parser) expectGTE(context string) error {
	t := p.s.next()
	if t.kind != tokGTE {
		return fmt.Errorf("httpql: %s: expected >=, got %q", context, t.val)
	}
	return nil
}

// isHTTPMethod reports whether s is a recognised HTTP method keyword.
func isHTTPMethod(s string) bool {
	switch s {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// isHintKeyword reports whether s is a query hint keyword.
func isHintKeyword(s string) bool {
	switch s {
	case "CONCURRENCY", "QUERY_TIMEOUT", "REQUEST_CACHE", "CACHE",
		"RETRY", "REDIRECTS", "STOP_WHEN":
		return true
	}
	return false
}

// parseFormValues parses a URL-encoded "key=value&key2=value2" string.
func parseFormValues(s string) url.Values {
	vals := url.Values{}
	for _, part := range strings.Split(s, "&") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			vals.Set(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
		} else {
			vals.Set(part, "")
		}
	}
	return vals
}
