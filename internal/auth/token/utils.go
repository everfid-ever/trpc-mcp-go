package token

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// startPeriodicCleanup will run cleanup on caches periodically.
func (v *TokenVerifier) startPeriodicCleanup() {
	interval := v.config.CacheConfig.CleanupInterval
	if interval <= 0 {
		interval = 10 * time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if v.jwkCache != nil {
				v.jwkCache.Cleanup()
			}
			if v.introspectionCache != nil {
				v.introspectionCache.Cleanup()
			}
		case <-v.stopCh:
			return
		}
	}
}

// warmupJWKCache fetches JWKS for configured issuers in background (best-effort)
func (v *TokenVerifier) warmupJWKCache() {
	ctx := context.Background()
	for _, iss := range v.config.Issuers {
		if iss.JWKSURI == "" {
			continue
		}
		go func(ic IssuerConfig) {
			_, err := v.fetchJWKS(ctx, ic.JWKSURI)
			if err != nil {
				// best effort, no failure
				fmt.Printf("warmup jwks failed for issuer %s: %v\n", ic.Issuer, err)
			}
		}(iss)
	}
}

// getPublicKey gets public key from cache or fetches and caches it.
func (v *TokenVerifier) getPublicKey(ctx context.Context, issuer, kid, alg string) (interface{}, error) {
	// check cache
	if v.jwkCache != nil {
		if e := v.jwkCache.Get(issuer, kid); e != nil {
			return e.Key, nil
		}
	}
	// use singleflight to avoid duplicate fetches
	cacheKey := fmt.Sprintf("%s:%s", issuer, kid)
	res, err, _ := v.sf.Do(cacheKey, func() (interface{}, error) {
		return v.fetchPublicKey(ctx, issuer, kid, alg)
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// fetchPublicKey obtains JWKS and extracts the key with matching kid.
func (v *TokenVerifier) fetchPublicKey(ctx context.Context, issuer, kid, alg string) (interface{}, error) {
	issuerCfg, ok := v.issuerMap[issuer]
	if !ok {
		return nil, fmt.Errorf("unknown issuer: %s", issuer)
	}
	v.metrics.mu.Lock()
	v.metrics.JWKSFetches++
	v.metrics.mu.Unlock()

	jwks, err := v.fetchJWKS(ctx, issuerCfg.JWKSURI)
	if err != nil {
		v.metrics.mu.Lock()
		v.metrics.JWKSFetchErrors++
		v.metrics.mu.Unlock()
		return nil, fmt.Errorf("fetch jwks failed: %w", err)
	}

	for _, j := range jwks.Keys {
		if j.KeyID == kid && (j.Algorithm == "" || j.Algorithm == alg) {
			pub, err := v.convertJWKToPublicKey(&j)
			if err != nil {
				continue
			}
			// cache it
			if v.jwkCache != nil {
				exp := time.Now().Add(v.config.CacheConfig.JWKCacheTTL)
				v.jwkCache.Set(issuer, kid, pub, j.Algorithm, exp)
			}
			return pub, nil
		}
	}
	return nil, fmt.Errorf("key %s not found in jwks", kid)
}

// fetchJWKS 获取JWKS
func (v *TokenVerifier) fetchJWKS(ctx context.Context, jwksURI string) (*JWKSet, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", jwksURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	var set JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	return &set, nil
}

// GetMetrics returns a copy of metrics
func (v *TokenVerifier) GetMetrics() *VerifierMetrics {
	v.metrics.mu.RLock()
	defer v.metrics.mu.RUnlock()
	copy := *v.metrics
	return &copy
}

// RefreshJWKS forces a refresh for an issuer's JWKS
func (v *TokenVerifier) RefreshJWKS(ctx context.Context, issuer string) error {
	ic, ok := v.issuerMap[issuer]
	if !ok {
		return fmt.Errorf("unknown issuer: %s", issuer)
	}
	_, err := v.fetchJWKS(ctx, ic.JWKSURI)
	return err
}
