package token

import (
	"sync"
	"time"
)

// IntrospectionCacheEntry 内省缓存条目
type IntrospectionCacheEntry struct {
	Response  *IntrospectionResponse
	ExpiresAt time.Time
	FetchedAt time.Time
}

// IntrospectionCache 内省缓存管理器
type IntrospectionCache struct {
	cache  map[string]*IntrospectionCacheEntry
	mu     sync.RWMutex
	config *CacheConfig
}

// Get 从缓存获取JWK
func (c *IntrospectionCache) Get(token string) *IntrospectionCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.cache[token]
	if !ok {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		return nil
	}
	return entry
}

// Set 设置JWK缓存
func (c *IntrospectionCache) Set(token string, resp *IntrospectionResponse, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.cache) >= c.config.MaxCacheSize {
		// simplistic eviction by oldest fetched
		oldest := ""
		var oldestT time.Time = time.Now()
		for t, e := range c.cache {
			if e.FetchedAt.Before(oldestT) {
				oldestT = e.FetchedAt
				oldest = t
			}
		}
		if oldest != "" {
			delete(c.cache, oldest)
		}
	}
	c.cache[token] = &IntrospectionCacheEntry{Response: resp, ExpiresAt: time.Now().Add(ttl), FetchedAt: time.Now()}
}

// Cleanup 清理过期的JWK缓存
func (c *IntrospectionCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for t, e := range c.cache {
		if now.After(e.ExpiresAt) {
			delete(c.cache, t)
		}
	}
}
