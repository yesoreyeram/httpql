package guardrails

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/semaphore"
)

// SemaphorePool manages a hierarchy of weighted semaphores:
//
//	Global requests → Namespace queries → Per-query requests → Per-origin requests
//
// Every layer must be acquired before an HTTP request is issued.  Releasing a
// layer is done via the returned Release function; callers must always defer
// that call.
//
// SemaphorePool is safe for concurrent use.
type SemaphorePool struct {
	mu sync.RWMutex

	// global limits
	globalRequests *semaphore.Weighted // total in-flight requests across all queries
	globalQueries  *semaphore.Weighted // total concurrent queries

	// per-namespace query semaphores  key → semaphore
	namespaceSems map[string]*semaphore.Weighted
	nsQueryMax    int64 // default per-namespace query concurrency

	// per-query request semaphores  key → semaphore
	querySems    map[string]*semaphore.Weighted
	queryReqMax  int64 // default per-query request concurrency

	// per-origin request semaphores  key → semaphore
	originSems    map[string]*semaphore.Weighted
	originReqMax  int64 // per-origin request concurrency
}

// SemaphorePoolConfig holds the limits used to initialise the pool.
type SemaphorePoolConfig struct {
	GlobalRequestsMax         int64
	GlobalQueriesMax          int64
	DefaultNSQueriesMax       int64
	DefaultQueryRequestsMax   int64
	DefaultOriginRequestsMax  int64
}

// NewSemaphorePool creates a ready-to-use SemaphorePool.
func NewSemaphorePool(cfg SemaphorePoolConfig) *SemaphorePool {
	return &SemaphorePool{
		globalRequests: semaphore.NewWeighted(cfg.GlobalRequestsMax),
		globalQueries:  semaphore.NewWeighted(cfg.GlobalQueriesMax),
		namespaceSems:  make(map[string]*semaphore.Weighted),
		nsQueryMax:     cfg.DefaultNSQueriesMax,
		querySems:      make(map[string]*semaphore.Weighted),
		queryReqMax:    cfg.DefaultQueryRequestsMax,
		originSems:     make(map[string]*semaphore.Weighted),
		originReqMax:   cfg.DefaultOriginRequestsMax,
	}
}

// AcquireQuery acquires the global query slot and the namespace query slot.
// Returns a release function that must be called (typically via defer) to
// return both slots.  Returns ErrConcurrencyLimit if ctx is cancelled while
// waiting.
func (p *SemaphorePool) AcquireQuery(ctx context.Context, namespace string) (release func(), err error) {
	if err := p.globalQueries.Acquire(ctx, 1); err != nil {
		return nil, &PolicyError{Code: ErrConcurrencyLimit, Detail: "global query concurrency limit reached"}
	}

	nsSem := p.getOrCreateNSSem(namespace)
	if err := nsSem.Acquire(ctx, 1); err != nil {
		p.globalQueries.Release(1)
		return nil, &PolicyError{Code: ErrConcurrencyLimit, Detail: fmt.Sprintf("namespace %q query concurrency limit reached", namespace)}
	}

	release = func() {
		nsSem.Release(1)
		p.globalQueries.Release(1)
	}
	return release, nil
}

// AcquireRequest acquires the global request slot, the per-query request slot,
// and the per-origin request slot.  Returns a release function.
func (p *SemaphorePool) AcquireRequest(ctx context.Context, queryID, origin string) (release func(), err error) {
	if err := p.globalRequests.Acquire(ctx, 1); err != nil {
		return nil, &PolicyError{Code: ErrConcurrencyLimit, Detail: "global request concurrency limit reached"}
	}

	qSem := p.getOrCreateQuerySem(queryID)
	if err := qSem.Acquire(ctx, 1); err != nil {
		p.globalRequests.Release(1)
		return nil, &PolicyError{Code: ErrConcurrencyLimit, Detail: fmt.Sprintf("query %q request concurrency limit reached", queryID)}
	}

	oSem := p.getOrCreateOriginSem(origin)
	if err := oSem.Acquire(ctx, 1); err != nil {
		qSem.Release(1)
		p.globalRequests.Release(1)
		return nil, &PolicyError{Code: ErrConcurrencyLimit, Detail: fmt.Sprintf("origin %q request concurrency limit reached", origin)}
	}

	release = func() {
		oSem.Release(1)
		qSem.Release(1)
		p.globalRequests.Release(1)
	}
	return release, nil
}

// EvictQuery removes per-query semaphore state once a query finishes.  This
// prevents unbounded map growth in long-running servers.
func (p *SemaphorePool) EvictQuery(queryID string) {
	p.mu.Lock()
	delete(p.querySems, queryID)
	p.mu.Unlock()
}

// GlobalRequestsAvailable returns the number of global request slots available.
// This is an instantaneous snapshot — not a guarantee.
func (p *SemaphorePool) GlobalRequestsAvailable(total int64) int64 {
	// semaphore.Weighted doesn't expose Available(); we track via TryAcquire.
	// This implementation uses a lightweight probe approach for metrics.
	// A zero return means the pool is at capacity.
	if p.globalRequests.TryAcquire(1) {
		p.globalRequests.Release(1)
		return 1 // at least one available
	}
	return 0
}

// ─── private ─────────────────────────────────────────────────────────────────

func (p *SemaphorePool) getOrCreateNSSem(ns string) *semaphore.Weighted {
	p.mu.RLock()
	s, ok := p.namespaceSems[ns]
	p.mu.RUnlock()
	if ok {
		return s
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	// Double-checked locking.
	if s, ok = p.namespaceSems[ns]; ok {
		return s
	}
	s = semaphore.NewWeighted(p.nsQueryMax)
	p.namespaceSems[ns] = s
	return s
}

func (p *SemaphorePool) getOrCreateQuerySem(queryID string) *semaphore.Weighted {
	p.mu.RLock()
	s, ok := p.querySems[queryID]
	p.mu.RUnlock()
	if ok {
		return s
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok = p.querySems[queryID]; ok {
		return s
	}
	s = semaphore.NewWeighted(p.queryReqMax)
	p.querySems[queryID] = s
	return s
}

func (p *SemaphorePool) getOrCreateOriginSem(origin string) *semaphore.Weighted {
	p.mu.RLock()
	s, ok := p.originSems[origin]
	p.mu.RUnlock()
	if ok {
		return s
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if s, ok = p.originSems[origin]; ok {
		return s
	}
	s = semaphore.NewWeighted(p.originReqMax)
	p.originSems[origin] = s
	return s
}
