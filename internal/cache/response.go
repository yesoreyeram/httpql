package cache

import (
	"context"
	"sync"
	"time"
)

// Row represents a single extracted data row.
type Row map[string]interface{}

// ResponseEntry is a cached set of extracted rows from a completed query.
type ResponseEntry struct {
	Rows      []Row
	ExpiresAt time.Time
	// StaleAt is the time after which the entry is stale but may be served
	// while revalidation happens in the background (stale-while-revalidate).
	StaleAt time.Time
	// Namespace is stored for isolation assertion during retrieval.
	Namespace string
}

// IsExpired reports whether the entry has passed its hard TTL expiry.
func (e *ResponseEntry) IsExpired() bool {
	return !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt)
}

// IsStale reports whether the entry is past its freshness threshold but
// within the stale-while-revalidate window.
func (e *ResponseEntry) IsStale() bool {
	return !e.StaleAt.IsZero() && time.Now().After(e.StaleAt) && !e.IsExpired()
}

// ResponseCacheLookup is the result of a cache lookup.
type ResponseCacheLookup struct {
	Entry *ResponseEntry
	Hit   bool
	Stale bool // true if the entry is stale (SWR)
}

// ResponseCache is an in-memory, thread-safe extracted-rows cache.
// Namespace isolation is enforced: the cache key always includes the namespace,
// so one namespace can never retrieve another's rows even with an identical
// query fingerprint.
type ResponseCache struct {
	mu           sync.RWMutex
	entries      map[string]*responseLRUEntry
	order        []string
	maxEntries   int
	maxBytes     int64
	currentBytes int64
	maxRows      int
}

type responseLRUEntry struct {
	key   string
	value ResponseEntry
	bytes int64
}

// NewResponseCache creates a ResponseCache with the given limits.
func NewResponseCache(maxEntries int, maxBytes int64, maxRowsPerEntry int) *ResponseCache {
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	if maxBytes <= 0 {
		maxBytes = 500 * 1024 * 1024
	}
	if maxRowsPerEntry <= 0 {
		maxRowsPerEntry = 10_000
	}
	return &ResponseCache{
		entries:    make(map[string]*responseLRUEntry),
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		maxRows:    maxRowsPerEntry,
	}
}

// Get retrieves a cached response entry for the given namespace-scoped key.
// It enforces namespace isolation by checking that the stored entry's namespace
// matches the requested namespace — this is a defence-in-depth check since the
// key already encodes the namespace.
func (c *ResponseCache) Get(_ context.Context, namespace, key string) ResponseCacheLookup {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return ResponseCacheLookup{}
	}

	// Namespace isolation defence-in-depth check.
	if e.value.Namespace != namespace {
		// This should never happen if keys are generated correctly.
		// Treat as a cache miss and evict the inconsistent entry.
		c.mu.Lock()
		c.evictKey(key)
		c.mu.Unlock()
		return ResponseCacheLookup{}
	}

	if e.value.IsExpired() {
		c.mu.Lock()
		c.evictKey(key)
		c.mu.Unlock()
		return ResponseCacheLookup{}
	}

	v := e.value // copy metadata
	rows := make([]Row, len(v.Rows))
	copy(rows, v.Rows)
	v.Rows = rows

	return ResponseCacheLookup{
		Entry: &v,
		Hit:   true,
		Stale: v.IsStale(),
	}
}

// Set stores an extracted-rows entry.  Entries exceeding maxRowsPerEntry are
// not cached.  A zero ttl means the entry never expires.
func (c *ResponseCache) Set(_ context.Context, namespace, key string, rows []Row, ttl, swr time.Duration) {
	if len(rows) > c.maxRows {
		// Too many rows — don't cache partial results.
		return
	}

	entry := ResponseEntry{
		Rows:      rows,
		Namespace: namespace,
	}
	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
		if swr > 0 {
			// StaleAt = ExpiresAt - swr (entry becomes stale before it expires)
			entry.StaleAt = time.Now().Add(ttl - swr)
		}
	}

	size := int64(len(rows) * 128) // rough per-row size estimate

	c.mu.Lock()
	defer c.mu.Unlock()

	if old, ok := c.entries[key]; ok {
		c.currentBytes -= old.bytes
		c.removeFromOrder(key)
	}

	for len(c.entries) >= c.maxEntries || (c.maxBytes > 0 && c.currentBytes+size > c.maxBytes) {
		if len(c.order) == 0 {
			return
		}
		c.evictKey(c.order[0])
	}

	c.entries[key] = &responseLRUEntry{key: key, value: entry, bytes: size}
	c.order = append(c.order, key)
	c.currentBytes += size
}

// PurgeNamespace removes all entries belonging to namespace.
func (c *ResponseCache) PurgeNamespace(namespace string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for key, e := range c.entries {
		if e.value.Namespace == namespace {
			c.evictKey(key)
		}
	}
}

// Purge removes all entries.
func (c *ResponseCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*responseLRUEntry)
	c.order = nil
	c.currentBytes = 0
}

// Len returns the number of entries in the cache.
func (c *ResponseCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// evictKey removes key.  Must be called with c.mu held (write).
func (c *ResponseCache) evictKey(key string) {
	if e, ok := c.entries[key]; ok {
		c.currentBytes -= e.bytes
		delete(c.entries, key)
		c.removeFromOrder(key)
	}
}

func (c *ResponseCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}
