// Package interpolate expands ${...} placeholders in httpql query strings.
//
// # Supported placeholder types
//
//	${secret:KEY}
//
// Looks up KEY through the engine's configured secrets backend (env, vault,
// Kubernetes Secrets, or AWS SSM Parameter Store).  The key format depends on
// the active backend — see the secrets documentation for details.
//
//	${response:NAME.body.JSON_PATH}
//
// Extracts a value from the JSON body of a previously executed named request.
// NAME must match a datasource alias declared in the WITH block.  JSON_PATH is
// a dot-bracket path such as "token", "data.id", or "items[0].name".
//
//	${response:NAME.header.HEADER_NAME}
//
// Returns the value of the named HTTP response header from a previously
// executed request.
//
//	${response:NAME.status}
//
// Returns the HTTP status code (e.g. "200") of a previously executed request.
//
// # Security
//
// The ${env:...} placeholder is explicitly blocked.  Queries must never
// reference environment variables directly; all secrets must go through the
// configured secrets backend using ${secret:KEY}.  This ensures that secret
// access is audited, rate-limited, and controlled by the admin-configured
// backend regardless of the environment the engine runs in.
//
// # Usage
//
//	expanded, err := interpolate.Expand(ctx, rawText, secretProvider, responses)
//	if err != nil {
//	    // placeholder resolution failed
//	}
//
// CountSecretRefs counts how many ${secret:...} placeholders are in text
// without performing any resolution.  The count is used at plan-validation
// time to enforce MaxSecretRefsPerQuery.
package interpolate

import (
	"context"
	"fmt"
	"strings"

	"github.com/yesoreyeram/httpql/internal/secrets"
)

// Response holds the data from a completed HTTP request that can be referenced
// by subsequent requests through ${response:...} placeholders.
type Response struct {
	// StatusCode is the HTTP status code (e.g. 200).
	StatusCode int
	// Headers contains the response headers (canonical header names).
	Headers map[string]string
	// Body contains the raw response body bytes.
	Body []byte
}

// Expand replaces every ${...} placeholder in text with its resolved value.
//
// Supported placeholder types:
//
//   - ${secret:KEY}                     secret lookup via secretProvider
//   - ${response:NAME.body.JSON_PATH}   JSON body field from a prior response
//   - ${response:NAME.header.HDR_NAME}  header value from a prior response
//   - ${response:NAME.status}           HTTP status code of a prior response
//
// The ${env:...} placeholder is explicitly rejected: callers must use
// ${secret:KEY} to ensure all secret access goes through the configured backend.
//
// responses may be nil if no prior responses are available (simple single-request
// queries with only ${secret:...} placeholders).
//
// Expand is safe for concurrent use.
func Expand(ctx context.Context, text string, sp secrets.Provider, responses map[string]Response) (string, error) {
	if !strings.Contains(text, "${") {
		return text, nil
	}
	return expandAll(ctx, text, sp, responses)
}

// CountSecretRefs returns the number of ${secret:...} placeholders in text.
// It is used at plan-validation time to enforce MaxSecretRefsPerQuery.
func CountSecretRefs(text string) int {
	return countPrefix(text, "${secret:")
}

// CountResponseRefs returns the number of ${response:...} placeholders in text.
// It is used at plan-validation time to count chaining references.
func CountResponseRefs(text string) int {
	return countPrefix(text, "${response:")
}

// HasEnvRef reports whether text contains a blocked ${env:...} placeholder.
func HasEnvRef(text string) bool {
	return strings.Contains(text, "${env:")
}

// ─── internal ─────────────────────────────────────────────────────────────────

// expandAll iterates through text and resolves all ${...} occurrences.
func expandAll(ctx context.Context, text string, sp secrets.Provider, responses map[string]Response) (string, error) {
	var b strings.Builder
	b.Grow(len(text))
	rest := text
	for {
		start := strings.Index(rest, "${")
		if start < 0 {
			b.WriteString(rest)
			break
		}
		b.WriteString(rest[:start])
		rest = rest[start:]

		end := strings.Index(rest, "}")
		if end < 0 {
			// No closing brace — treat literally.
			b.WriteString(rest)
			break
		}
		inner := rest[2:end] // content between ${ and }
		rest = rest[end+1:]

		val, err := resolvePlaceholder(ctx, inner, sp, responses)
		if err != nil {
			return "", err
		}
		b.WriteString(val)
	}
	return b.String(), nil
}

// resolvePlaceholder resolves a single placeholder's inner content.
func resolvePlaceholder(ctx context.Context, inner string, sp secrets.Provider, responses map[string]Response) (string, error) {
	switch {
	case strings.HasPrefix(inner, "env:"):
		return "", fmt.Errorf("interpolate: ${env:...} is not allowed in queries; use ${secret:KEY} to access secrets through the configured backend")

	case strings.HasPrefix(inner, "secret:"):
		key := strings.TrimPrefix(inner, "secret:")
		if key == "" {
			return "", fmt.Errorf("interpolate: ${secret:} requires a non-empty key")
		}
		if sp == nil {
			return "", fmt.Errorf("interpolate: ${secret:%s}: no secrets provider configured", key)
		}
		val, err := sp.Lookup(ctx, key)
		if err != nil {
			return "", fmt.Errorf("interpolate: ${secret:%s}: %w", key, err)
		}
		return val, nil

	case strings.HasPrefix(inner, "response:"):
		return resolveResponse(inner[len("response:"):], responses)

	default:
		return "", fmt.Errorf("interpolate: unknown placeholder type %q; supported: secret, response", inner)
	}
}

// resolveResponse resolves a ${response:...} placeholder.
// ref has the form: NAME.body.PATH | NAME.header.HEADERNAME | NAME.status
func resolveResponse(ref string, responses map[string]Response) (string, error) {
	dot := strings.Index(ref, ".")
	if dot < 0 {
		return "", fmt.Errorf("interpolate: ${response:%s}: expected NAME.body.PATH, NAME.header.NAME, or NAME.status", ref)
	}
	name := ref[:dot]
	remainder := ref[dot+1:]

	if responses == nil {
		return "", fmt.Errorf("interpolate: ${response:%s}: no prior responses available", name)
	}
	resp, ok := responses[name]
	if !ok {
		return "", fmt.Errorf("interpolate: ${response:%s}: request %q has not been executed yet", name, name)
	}

	switch {
	case remainder == "status":
		return fmt.Sprintf("%d", resp.StatusCode), nil

	case strings.HasPrefix(remainder, "header."):
		hName := strings.TrimPrefix(remainder, "header.")
		if hName == "" {
			return "", fmt.Errorf("interpolate: ${response:%s.header.}: header name must not be empty", name)
		}
		// Case-insensitive header lookup.
		for k, v := range resp.Headers {
			if strings.EqualFold(k, hName) {
				return v, nil
			}
		}
		return "", fmt.Errorf("interpolate: ${response:%s.header.%s}: header not present in response", name, hName)

	case strings.HasPrefix(remainder, "body."):
		path := strings.TrimPrefix(remainder, "body.")
		if path == "" {
			return "", fmt.Errorf("interpolate: ${response:%s.body.}: JSON path must not be empty", name)
		}
		return extractJSON(resp.Body, path)

	default:
		return "", fmt.Errorf("interpolate: ${response:%s.%s}: expected body.PATH, header.NAME, or status", name, remainder)
	}
}

// countPrefix counts non-overlapping occurrences of prefix in s.
func countPrefix(s, prefix string) int {
	n := 0
	for {
		idx := strings.Index(s, prefix)
		if idx < 0 {
			break
		}
		// Advance past the opening ${ to find the closing }.
		from := idx + len(prefix)
		end := strings.Index(s[from:], "}")
		if end < 0 {
			break
		}
		n++
		s = s[from+end+1:]
	}
	return n
}
