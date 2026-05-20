package cache_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/yesoreyeram/httpql/internal/cache"
)

// ─── Cache key tests ─────────────────────────────────────────────────────────

func TestRequestCacheKey_IsDeterministic(t *testing.T) {
	t.Parallel()
	k1 := cache.RequestCacheKey("ns1", "GET", "https://api.example.com/data", nil, nil)
	k2 := cache.RequestCacheKey("ns1", "GET", "https://api.example.com/data", nil, nil)
	if k1 != k2 {
		t.Error("cache key must be deterministic")
	}
}

func TestRequestCacheKey_DiffersAcrossNamespaces(t *testing.T) {
	t.Parallel()
	k1 := cache.RequestCacheKey("ns1", "GET", "https://api.example.com/data", nil, nil)
	k2 := cache.RequestCacheKey("ns2", "GET", "https://api.example.com/data", nil, nil)
	if k1 == k2 {
		t.Error("cache key must differ across namespaces")
	}
}

func TestRequestCacheKey_ExcludesAuthorizationHeader(t *testing.T) {
	t.Parallel()

	headers := map[string]string{
		"Authorization": "Bearer secret-token-abc",
		"Content-Type":  "application/json",
	}
	k1 := cache.RequestCacheKey("ns", "GET", "https://api.example.com", headers, nil)

	// Change the auth token — key must NOT change.
	headers2 := map[string]string{
		"Authorization": "Bearer completely-different-token",
		"Content-Type":  "application/json",
	}
	k2 := cache.RequestCacheKey("ns", "GET", "https://api.example.com", headers2, nil)

	if k1 != k2 {
		t.Error("cache key must NOT include Authorization header value")
	}
}

func TestRequestCacheKey_ExcludesAllSensitiveHeaders(t *testing.T) {
	t.Parallel()

	sensitiveHeaders := []string{
		"Authorization",
		"Proxy-Authorization",
		"X-Api-Key",
		"X-Auth-Token",
		"X-Secret-Value",
		"Cookie",
		"Set-Cookie",
	}

	baseKey := cache.RequestCacheKey("ns", "GET", "https://api.example.com", nil, nil)

	for _, h := range sensitiveHeaders {
		headers := map[string]string{h: "super-secret-value"}
		k := cache.RequestCacheKey("ns", "GET", "https://api.example.com", headers, nil)
		if k != baseKey {
			t.Errorf("adding sensitive header %q should not change the cache key", h)
		}
	}
}

func TestRequestCacheKey_IncludesNonSensitiveHeaders(t *testing.T) {
	t.Parallel()

	k1 := cache.RequestCacheKey("ns", "GET", "https://api.example.com",
		map[string]string{"Accept": "application/json"}, nil)
	k2 := cache.RequestCacheKey("ns", "GET", "https://api.example.com",
		map[string]string{"Accept": "text/plain"}, nil)

	if k1 == k2 {
		t.Error("non-sensitive header differences must affect the cache key")
	}
}

func TestResponseCacheKey_NamespaceIsolation(t *testing.T) {
	t.Parallel()
	queryFP := "same-fingerprint"
	k1 := cache.ResponseCacheKey("ns1", queryFP)
	k2 := cache.ResponseCacheKey("ns2", queryFP)
	if k1 == k2 {
		t.Error("response cache keys must differ across namespaces")
	}
}

func TestAssertNamespaceIsolation_DifferentNamespaces(t *testing.T) {
	t.Parallel()
	if err := cache.AssertNamespaceIsolation("ns1", "ns2", "fp"); err != nil {
		t.Errorf("expected no isolation violation: %v", err)
	}
}

func TestDescribeKey_NeverIncludesSensitiveHeaderValues(t *testing.T) {
	t.Parallel()
	headers := map[string]string{
		"Authorization": "Bearer secret",
		"Accept":        "application/json",
	}
	info := cache.DescribeKey("ns", "GET", "https://api.example.com", headers, nil)

	// Excluded list must contain "authorization".
	found := false
	for _, h := range info.ExcludedHeaders {
		if h == "authorization" {
			found = true
		}
	}
	if !found {
		t.Error("DescribeKey must list 'authorization' in ExcludedHeaders")
	}

	// Included list must contain "accept".
	found = false
	for _, h := range info.IncludedHeaders {
		if h == "accept" {
			found = true
		}
	}
	if !found {
		t.Error("DescribeKey must list 'accept' in IncludedHeaders")
	}
}

// ─── RequestCache ─────────────────────────────────────────────────────────────

func TestRequestCache_SetAndGet(t *testing.T) {
	t.Parallel()
	c := cache.NewRequestCache(100, 1024*1024)
	ctx := context.Background()

	entry := cache.RequestEntry{
		StatusCode: 200,
		Body:       []byte(`{"data": "value"}`),
	}
	c.Set(ctx, "key1", entry, 60*time.Second)

	got, ok := c.Get(ctx, "key1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if string(got.Body) != string(entry.Body) {
		t.Errorf("cached body mismatch: got %q", got.Body)
	}
}

func TestRequestCache_MissForUnknownKey(t *testing.T) {
	t.Parallel()
	c := cache.NewRequestCache(100, 1024*1024)
	_, ok := c.Get(context.Background(), "nonexistent")
	if ok {
		t.Error("expected cache miss for unknown key")
	}
}

func TestRequestCache_RespectsExpiry(t *testing.T) {
	t.Parallel()
	c := cache.NewRequestCache(100, 1024*1024)
	ctx := context.Background()

	c.Set(ctx, "key1", cache.RequestEntry{Body: []byte("body")}, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	_, ok := c.Get(ctx, "key1")
	if ok {
		t.Error("expected cache miss after TTL expiry — stale entries must never be served")
	}
}

func TestRequestCache_EnforcesMaxEntries(t *testing.T) {
	t.Parallel()
	c := cache.NewRequestCache(3, 1024*1024)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Set(ctx, key, cache.RequestEntry{Body: []byte("x")}, 60*time.Second)
	}

	if c.Len() > 3 {
		t.Errorf("cache exceeded max entries: got %d, want ≤ 3", c.Len())
	}
}

func TestRequestCache_Purge(t *testing.T) {
	t.Parallel()
	c := cache.NewRequestCache(100, 1024*1024)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key%d", i)
		c.Set(ctx, key, cache.RequestEntry{Body: []byte("x")}, 60*time.Second)
	}
	c.Purge()
	if c.Len() != 0 {
		t.Errorf("expected 0 entries after purge, got %d", c.Len())
	}
}

func TestRequestCache_ZeroTTLNeverExpires(t *testing.T) {
	t.Parallel()
	c := cache.NewRequestCache(100, 1024*1024)
	ctx := context.Background()

	c.Set(ctx, "forever", cache.RequestEntry{Body: []byte("x")}, 0)
	_, ok := c.Get(ctx, "forever")
	if !ok {
		t.Error("expected cache hit for zero-TTL entry")
	}
}

// ─── ResponseCache ────────────────────────────────────────────────────────────

func TestResponseCache_SetAndGet(t *testing.T) {
	t.Parallel()
	c := cache.NewResponseCache(100, 1024*1024, 1000)
	ctx := context.Background()

	rows := []cache.Row{{"id": 1}, {"id": 2}}
	key := cache.ResponseCacheKey("ns1", "fp1")
	c.Set(ctx, "ns1", key, rows, 60*time.Second, 0)

	result := c.Get(ctx, "ns1", key)
	if !result.Hit {
		t.Fatal("expected cache hit")
	}
	if len(result.Entry.Rows) != 2 {
		t.Errorf("expected 2 rows, got %d", len(result.Entry.Rows))
	}
}

func TestResponseCache_NamespaceIsolation(t *testing.T) {
	t.Parallel()
	c := cache.NewResponseCache(100, 1024*1024, 1000)
	ctx := context.Background()

	// Store under ns1 key.
	key := cache.ResponseCacheKey("ns1", "same-fp")
	rows := []cache.Row{{"secret": "ns1-data"}}
	c.Set(ctx, "ns1", key, rows, 60*time.Second, 0)

	// Try to read under ns2 with the same fingerprint — must miss.
	ns2Key := cache.ResponseCacheKey("ns2", "same-fp")
	result := c.Get(ctx, "ns2", ns2Key)
	if result.Hit {
		t.Error("namespace isolation violation: ns2 should not read ns1 cache entries")
	}
}

func TestResponseCache_RespectsExpiry(t *testing.T) {
	t.Parallel()
	c := cache.NewResponseCache(100, 1024*1024, 1000)
	ctx := context.Background()

	key := cache.ResponseCacheKey("ns1", "fp1")
	c.Set(ctx, "ns1", key, []cache.Row{{"x": 1}}, 10*time.Millisecond, 0)
	time.Sleep(20 * time.Millisecond)

	result := c.Get(ctx, "ns1", key)
	if result.Hit {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestResponseCache_PurgeNamespace(t *testing.T) {
	t.Parallel()
	c := cache.NewResponseCache(100, 1024*1024, 1000)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		key := cache.ResponseCacheKey("ns1", fmt.Sprintf("fp%d", i))
		c.Set(ctx, "ns1", key, []cache.Row{{"x": i}}, 60*time.Second, 0)
	}
	key2 := cache.ResponseCacheKey("ns2", "fp0")
	c.Set(ctx, "ns2", key2, []cache.Row{{"x": 99}}, 60*time.Second, 0)

	c.PurgeNamespace("ns1")

	// ns1 entries should be gone.
	for i := 0; i < 5; i++ {
		key := cache.ResponseCacheKey("ns1", fmt.Sprintf("fp%d", i))
		if c.Get(ctx, "ns1", key).Hit {
			t.Errorf("expected ns1 entry %d to be purged", i)
		}
	}

	// ns2 entry should survive.
	if !c.Get(ctx, "ns2", key2).Hit {
		t.Error("ns2 entry should survive ns1 purge")
	}
}

func TestResponseCache_StaleWhileRevalidate(t *testing.T) {
	t.Parallel()
	c := cache.NewResponseCache(100, 1024*1024, 1000)
	ctx := context.Background()

	// TTL=50ms, SWR=30ms → StaleAt = now+20ms, ExpiresAt = now+50ms
	key := cache.ResponseCacheKey("ns1", "fp1")
	c.Set(ctx, "ns1", key, []cache.Row{{"x": 1}}, 50*time.Millisecond, 30*time.Millisecond)

	time.Sleep(25 * time.Millisecond) // past StaleAt but before ExpiresAt

	result := c.Get(ctx, "ns1", key)
	if !result.Hit {
		t.Fatal("expected cache hit within SWR window")
	}
	if !result.Stale {
		t.Error("expected entry to be marked stale within SWR window")
	}
}

func TestResponseCache_RejectsEntriesExceedingMaxRows(t *testing.T) {
	t.Parallel()
	c := cache.NewResponseCache(100, 1024*1024, 3) // maxRowsPerEntry = 3
	ctx := context.Background()

	rows := make([]cache.Row, 10) // > 3
	for i := range rows {
		rows[i] = cache.Row{"id": i}
	}
	key := cache.ResponseCacheKey("ns1", "fp1")
	c.Set(ctx, "ns1", key, rows, 60*time.Second, 0)

	// Should not be cached.
	if c.Get(ctx, "ns1", key).Hit {
		t.Error("entries exceeding maxRowsPerEntry must not be cached")
	}
}

// end of file
