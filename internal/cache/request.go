package cache

import (
	"context"
	"sync"
	"time"
)

// RequestEntry is a single cached HTTP response body.
type RequestEntry struct {
	Body       []byte
	StatusCode int
	Headers    map[string]string
	ExpiresAt  time.Time
}

// IsExpired reports whether the entry has passed its TTL.
func (e *RequestEntry) IsExpired() bool {
	return !e.ExpiresAt.IsZero() && time.Now().After(e.ExpiresAt)
}

// RequestCache is an in-memory, thread-safe HTTP-response cache.
// It enforces:
//   - TTL expiry (entries past their TTL are never served)
//   - Maximum entry count (LRU eviction when at capacity)
//   - Maximum total byte size
//   - Namespace isolation via keying (enforced by the key function)
//
// Auth and secret values are never stored here — that invariant is enforced
// in the key computation layer (cache.RequestCacheKey).
type RequestCache struct {
	mu          sync.RWMutex
	entries     map[string]*requestLRUEntry
	order       []string // insertion order for simple eviction
	maxEntries  int
	maxBytes    int64
	currentBytes int64
}

type requestLRUEntry struct {
	key   string
	value RequestEntry
	bytes int64
}

// NewRequestCache creates a RequestCache with the given limits.
// maxEntries=0 or maxBytes=0 disables the respective limit.
func NewRequestCache(maxEntries int, maxBytes int64) *RequestCache {
	if maxEntries <= 0 {
		maxEntries = 10_000
	}
	if maxBytes <= 0 {
		maxBytes = 100 * 1024 * 1024
	}
	return &RequestCache{
		entries:    make(map[string]*requestLRUEntry),
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
	}
}

// Get returns the cached entry for key and true, or nil and false if the
// entry does not exist or has expired.
func (c *RequestCache) Get(_ context.Context, key string) (*RequestEntry, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok {
		return nil, false
	}
	if e.value.IsExpired() {
		c.mu.Lock()
		c.evictKey(key)
		c.mu.Unlock()
		return nil, false
	}
	v := e.value // copy
	return &v, true
}

// Set stores an entry.  If the cache is at capacity, the oldest entry is
// evicted.  A zero ttl means the entry never expires (within the cache).
func (c *RequestCache) Set(_ context.Context, key string, entry RequestEntry, ttl time.Duration) {
	size := int64(len(entry.Body))

	// Clamp size to prevent a single huge entry from owning the whole cache.
	if size > c.maxBytes {
		return
	}

	if ttl > 0 {
		entry.ExpiresAt = time.Now().Add(ttl)
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict existing entry for this key if present.
	if old, ok := c.entries[key]; ok {
		c.currentBytes -= old.bytes
		c.removeFromOrder(key)
	}

	// Evict oldest entries until we have room.
	for len(c.entries) >= c.maxEntries || (c.maxBytes > 0 && c.currentBytes+size > c.maxBytes) {
		if len(c.order) == 0 {
			return
		}
		c.evictKey(c.order[0])
	}

	c.entries[key] = &requestLRUEntry{key: key, value: entry, bytes: size}
	c.order = append(c.order, key)
	c.currentBytes += size
}

// Purge removes all entries.
func (c *RequestCache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*requestLRUEntry)
	c.order = nil
	c.currentBytes = 0
}

// Len returns the number of entries currently in the cache.
func (c *RequestCache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// ByteSize returns the approximate total bytes currently cached.
func (c *RequestCache) ByteSize() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentBytes
}

// evictKey removes key from the cache.  Must be called with c.mu held (write).
func (c *RequestCache) evictKey(key string) {
	if e, ok := c.entries[key]; ok {
		c.currentBytes -= e.bytes
		delete(c.entries, key)
		c.removeFromOrder(key)
	}
}

func (c *RequestCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}
