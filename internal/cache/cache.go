// Package cache provides a sharded, size-bounded TTL cache with request coalescing.
package cache

import (
	"errors"
	"hash/maphash"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const numShards = 256

// ErrSkip may be returned by a loader to report "absent" without caching the result.
var ErrSkip = errors.New("cache: skip")

type entry[V any] struct {
	v   V
	exp int64
}

type shard[V any] struct {
	mu sync.RWMutex
	m  map[string]entry[V]
}

// Cache is a sharded, size-bounded cache with TTL expiration and request
// coalescing for concurrent loads of the same key.
type Cache[V any] struct {
	shards   [numShards]shard[V]
	seed     maphash.Seed
	ttl      time.Duration
	maxShard int
	group    singleflight.Group
}

// New creates a cache with the supplied item lifetime and approximate capacity.
func New[V any](ttl time.Duration, maxEntries int) *Cache[V] {
	c := &Cache[V]{seed: maphash.MakeSeed(), ttl: ttl, maxShard: max(1, maxEntries/numShards)}
	for i := range c.shards {
		c.shards[i].m = make(map[string]entry[V])
	}
	return c
}

func (c *Cache[V]) shard(k string) *shard[V] {
	return &c.shards[maphash.String(c.seed, k)%numShards]
}

// Get returns a non-expired value for k, if present.
func (c *Cache[V]) Get(k string) (V, bool) {
	s := c.shard(k)
	s.mu.RLock()
	e, ok := s.m[k]
	s.mu.RUnlock()
	if !ok || time.Now().UnixNano() > e.exp {
		var zero V
		return zero, false
	}
	return e.v, true
}

// Set stores v under k and refreshes its expiration time.
func (c *Cache[V]) Set(k string, v V) {
	s := c.shard(k)
	now := time.Now().UnixNano()
	s.mu.Lock()
	if _, exists := s.m[k]; !exists && len(s.m) >= c.maxShard {
		// Go's randomized map iteration gives cheap approximate-random eviction.
		scanned, evicted := 0, 0
		for key, e := range s.m {
			if evicted == 0 || now > e.exp {
				delete(s.m, key)
				evicted++
			}
			if scanned++; scanned >= 32 {
				break
			}
		}
	}
	s.m[k] = entry[V]{v: v, exp: now + int64(c.ttl)}
	s.mu.Unlock()
}

// Delete removes k from the cache.
func (c *Cache[V]) Delete(k string) {
	s := c.shard(k)
	s.mu.Lock()
	delete(s.m, k)
	s.mu.Unlock()
}

// GetOrLoad returns the cached value, or runs load once per key across concurrent callers.
func (c *Cache[V]) GetOrLoad(k string, load func() (V, error)) (V, error) {
	if v, ok := c.Get(k); ok {
		return v, nil
	}
	r, err, _ := c.group.Do(k, func() (any, error) {
		if v, ok := c.Get(k); ok {
			return v, nil
		}
		v, err := load()
		if err == nil {
			c.Set(k, v)
		}
		return v, err
	})
	if err != nil {
		var zero V
		return zero, err
	}
	if r == nil {
		var zero V
		return zero, nil
	}
	return r.(V), nil
}
