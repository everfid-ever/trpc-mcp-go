package token

import (
	"fmt"
	"time"
)

// VerifierConfig JWT验证器配置
type VerifierConfig struct {
	// 本地验证配置
	LocalVerification LocalVerificationConfig `json:"local_verification"`

	// 远程验证配置
	RemoteVerification RemoteVerificationConfig `json:"remote_verification"`

	// 缓存配置
	CacheConfig CacheConfig `json:"cache_config"`

	// 发行者配置
	Issuers []IssuerConfig `json:"issuers"`

	// 时钟偏移容忍度
	ClockSkew time.Duration `json:"clock_skew"`

	// 验证策略
	VerificationStrategy VerificationStrategy `json:"verification_strategy"`

	// 监控配置
	MetricsConfig MetricsConfig `json:"metrics_config"`
}

// LocalVerificationConfig 本地验证配置
type LocalVerificationConfig struct {
	Enabled             bool          `json:"enabled"`
	SupportedAlgorithms []string      `json:"supported_algorithms"` // RS256, ES256, etc.
	JWKSRefreshInterval time.Duration `json:"jwks_refresh_interval"`
	JWKSTimeout         time.Duration `json:"jwks_timeout"`
}

// RemoteVerificationConfig 远程验证配置
type RemoteVerificationConfig struct {
	Enabled         bool          `json:"enabled"`
	Timeout         time.Duration `json:"timeout"`
	RetryAttempts   int           `json:"retry_attempts"`
	RetryInterval   time.Duration `json:"retry_interval"`
	FallbackEnabled bool          `json:"fallback_enabled"`
}

// CacheConfig 缓存配置
type CacheConfig struct {
	JWKCacheTTL           time.Duration `json:"jwk_cache_ttl"`
	IntrospectionCacheTTL time.Duration `json:"introspection_cache_ttl"`
	MaxCacheSize          int           `json:"max_cache_size"`
	CleanupInterval       time.Duration `json:"cleanup_interval"`
}

// IssuerConfig 发行者配置
type IssuerConfig struct {
	Issuer                string   `json:"issuer"`
	JWKSURI               string   `json:"jwks_uri"`
	IntrospectionEndpoint string   `json:"introspection_endpoint,omitempty"`
	ClientID              string   `json:"client_id,omitempty"`
	ClientSecret          string   `json:"client_secret,omitempty"`
	Audience              []string `json:"audience,omitempty"`
}

// VerificationStrategy 验证策略
type VerificationStrategy string

const (
	LocalFirst  VerificationStrategy = "local_first"  // 优先本地验证
	RemoteFirst VerificationStrategy = "remote_first" // 优先远程验证
	LocalOnly   VerificationStrategy = "local_only"   // 仅本地验证
	RemoteOnly  VerificationStrategy = "remote_only"  // 仅远程验证
	Hybrid      VerificationStrategy = "hybrid"       // 混合验证
)

// MetricsConfig 监控配置
type MetricsConfig struct {
	Enabled     bool   `json:"enabled"`
	Namespace   string `json:"namespace"`
	ServiceName string `json:"service_name"`
}

// 配置验证函数
func validateConfig(config *VerifierConfig) error {
	if len(config.Issuers) == 0 {
		return fmt.Errorf("at least one issuer must be configured")
	}

	for i, issuer := range config.Issuers {
		if issuer.Issuer == "" {
			return fmt.Errorf("issuer[%d]: issuer URL cannot be empty", i)
		}

		if config.LocalVerification.Enabled && issuer.JWKSURI == "" {
			return fmt.Errorf("issuer[%d]: JWKS URI is required for local verification", i)
		}

		if config.RemoteVerification.Enabled && issuer.IntrospectionEndpoint == "" {
			return fmt.Errorf("issuer[%d]: introspection endpoint is required for remote verification", i)
		}
	}

	if config.CacheConfig.JWKCacheTTL <= 0 {
		config.CacheConfig.JWKCacheTTL = 24 * time.Hour
	}

	if config.CacheConfig.IntrospectionCacheTTL <= 0 {
		config.CacheConfig.IntrospectionCacheTTL = 5 * time.Minute
	}

	if config.CacheConfig.MaxCacheSize <= 0 {
		config.CacheConfig.MaxCacheSize = 10000
	}

	if config.CacheConfig.CleanupInterval <= 0 {
		config.CacheConfig.CleanupInterval = 10 * time.Minute
	}

	return nil
}
