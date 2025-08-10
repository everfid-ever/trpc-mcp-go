package token

import (
	"golang.org/x/sync/singleflight"
	"net/http"
	"sync"
	"time"
)

// JWKCacheEntry JWK缓存条目
type JWKCacheEntry struct {
	Key       interface{}
	Algorithm string
	ExpiresAt time.Time
	FetchedAt time.Time
}

// JWKCache JWK缓存管理器
type JWKCache struct {
	cache      map[string]map[string]*JWKCacheEntry
	mu         sync.RWMutex
	config     *CacheConfig
	httpClient *http.Client
	sf         singleflight.Group
}

// Get 从缓存获取JWK
func (c *JWKCache) Get(issuer, kid string) *JWKCacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	issuerCache, ok := c.cache[issuer]
	if !ok {
		return nil
	}
	entry, ok := issuerCache[kid]
	if !ok {
		return nil
	}
	if time.Now().After(entry.ExpiresAt) {
		return nil
	}
	return entry
}

// Set 设置JWK缓存
func (c *JWKCache) Set(issuer, kid string, key interface{}, algorithm string, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.cache[issuer]; !ok {
		c.cache[issuer] = make(map[string]*JWKCacheEntry)
	}
	c.cache[issuer][kid] = &JWKCacheEntry{Key: key, Algorithm: algorithm, ExpiresAt: expiresAt, FetchedAt: time.Now()}
}

// Cleanup 清理过期的JWK缓存
func (c *JWKCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for iss, issCache := range c.cache {
		for kid, entry := range issCache {
			if now.After(entry.ExpiresAt) {
				delete(issCache, kid)
			}
		}
		if len(issCache) == 0 {
			delete(c.cache, iss)
		}
	}
}
