package token

import (
	"fmt"
	"golang.org/x/sync/singleflight"
	"net/http"
	"sync"
	"time"
)

// TokenVerifier 高性能JWT令牌验证器
type TokenVerifier struct {
	config             *VerifierConfig
	httpClient         *http.Client
	jwkCache           *JWKCache
	introspectionCache *IntrospectionCache
	metrics            *VerifierMetrics

	// 并发控制
	sf singleflight.Group
	mu sync.RWMutex

	// 发行者映射
	issuerMap map[string]*IssuerConfig

	// 停止信号
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewTokenVerifier 创建新的令牌验证器
func NewTokenVerifier(config *VerifierConfig) (*TokenVerifier, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// 设置默认值
	if config.ClockSkew == 0 {
		config.ClockSkew = 5 * time.Minute
	}
	if config.VerificationStrategy == "" {
		config.VerificationStrategy = LocalFirst
	}

	// 验证配置
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	// 创建HTTP客户端
	httpClient := &http.Client{
		Timeout: config.LocalVerification.JWKSTimeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// 创建JWK缓存
	jwkCache := &JWKCache{
		cache:      make(map[string]map[string]*JWKCacheEntry),
		config:     &config.CacheConfig,
		httpClient: httpClient,
	}

	// 创建内省缓存
	introspectionCache := &IntrospectionCache{
		cache:  make(map[string]*IntrospectionCacheEntry),
		config: &config.CacheConfig,
	}

	// 创建发行者映射
	issuerMap := make(map[string]*IssuerConfig)
	for i := range config.Issuers {
		issuer := &config.Issuers[i]
		issuerMap[issuer.Issuer] = issuer
	}

	// 创建监控指标
	metrics := &VerifierMetrics{}

	verifier := &TokenVerifier{
		config:             config,
		httpClient:         httpClient,
		jwkCache:           jwkCache,
		introspectionCache: introspectionCache,
		metrics:            metrics,
		issuerMap:          issuerMap,
		stopCh:             make(chan struct{}),
	}

	// 启动定期清理
	go verifier.startPeriodicCleanup()

	// 预热JWK缓存
	go verifier.warmupJWKCache()

	return verifier, nil
}

func (v *TokenVerifier) Close() error {
	v.stopOnce.Do(func() {
		close(v.stopCh)
	})
	return nil
}
