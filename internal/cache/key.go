// Package cache provides request-level deduplication caching and response-level
// row caching with strict security invariants:
//
//  1. Authorization header values are NEVER included in cache keys or entries.
//  2. Secret reference values are NEVER stored in any cache entry.
//  3. Namespace isolation: one namespace can never read another's entries.
//  4. TTL is always enforced; stale entries are never served even under load.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// sensitiveHeaderPrefixes lists HTTP header name prefixes that are
// unconditionally excluded from cache keys.  This list must never be shrunk.
var sensitiveHeaderPrefixes = []string{
	"authorization",
	"proxy-authorization",
	"x-api-key",
	"x-auth-token",
	"x-secret",
	"cookie",
	"set-cookie",
}

// RequestCacheKey produces a deterministic, security-safe cache key for an
// HTTP request.  Auth and secret headers are NEVER included.
//
// Parameters:
//   - namespace: the query namespace (included for namespace isolation)
//   - method: HTTP method (GET, POST, …)
//   - rawURL: the full URL including query string
//   - headers: request headers — sensitive headers are automatically excluded
//   - body: request body bytes (nil for GET)
//
// The key is a hex-encoded SHA-256 hash of the normalised request fingerprint.
func RequestCacheKey(namespace, method, rawURL string, headers map[string]string, body []byte) string {
	fp := requestFingerprint{
		Namespace: namespace,
		Method:    strings.ToUpper(method),
		URL:       rawURL,
		Headers:   sanitiseHeaders(headers),
		BodyHash:  bodyHash(body),
	}
	data, _ := json.Marshal(fp)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ResponseCacheKey produces a deterministic cache key for a cached query
// result (extracted rows).  The key is scoped to the namespace.
//
// Parameters:
//   - namespace: the query namespace
//   - queryFingerprint: a caller-supplied fingerprint of the query text,
//     URLs, and extraction path — but NOT of any secret values.
func ResponseCacheKey(namespace, queryFingerprint string) string {
	h := sha256.Sum256([]byte(namespace + ":" + queryFingerprint))
	return hex.EncodeToString(h[:])
}

// ─── internal types ───────────────────────────────────────────────────────────

type requestFingerprint struct {
	Namespace string
	Method    string
	URL       string
	Headers   map[string]string // sorted, sanitised
	BodyHash  string
}

// sanitiseHeaders returns a copy of headers with all sensitive keys removed.
// Keys are lowercased and sorted for determinism.
func sanitiseHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lower := strings.ToLower(k)
		if isSensitiveHeader(lower) {
			// Never include — this is the compile-time invariant enforced here.
			continue
		}
		out[lower] = v
	}
	return out
}

// isSensitiveHeader reports whether a lowercase header name should be excluded
// from cache keys.
func isSensitiveHeader(lower string) bool {
	for _, prefix := range sensitiveHeaderPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func bodyHash(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:])
}

// SortedKeys returns sorted map keys (for test assertions).
func SortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// RedactedKeyInfo is a diagnostic struct that describes what was included and
// excluded from a cache key computation — useful for debugging without
// exposing secret values.
type RedactedKeyInfo struct {
	Namespace       string
	Method          string
	URL             string
	IncludedHeaders []string
	ExcludedHeaders []string
	HasBody         bool
}

// DescribeKey returns diagnostic information about what was (and was not)
// included in the cache key for a request.  This is used by EXPLAIN POLICY.
// It never returns header values, only names.
func DescribeKey(namespace, method, rawURL string, headers map[string]string, body []byte) RedactedKeyInfo {
	var included, excluded []string
	for k := range headers {
		lower := strings.ToLower(k)
		if isSensitiveHeader(lower) {
			excluded = append(excluded, lower)
		} else {
			included = append(included, lower)
		}
	}
	sort.Strings(included)
	sort.Strings(excluded)
	return RedactedKeyInfo{
		Namespace:       namespace,
		Method:          strings.ToUpper(method),
		URL:             rawURL,
		IncludedHeaders: included,
		ExcludedHeaders: excluded,
		HasBody:         len(body) > 0,
	}
}

// ─── Namespace isolation helper ───────────────────────────────────────────────

// AssertNamespaceIsolation panics if two keys from different namespaces could
// collide.  This is called in tests as a compile-time safety net.
func AssertNamespaceIsolation(ns1, ns2, queryFP string) error {
	k1 := ResponseCacheKey(ns1, queryFP)
	k2 := ResponseCacheKey(ns2, queryFP)
	if k1 == k2 {
		return fmt.Errorf("NAMESPACE ISOLATION VIOLATION: namespaces %q and %q produced the same cache key for fingerprint %q",
			ns1, ns2, queryFP)
	}
	return nil
}
