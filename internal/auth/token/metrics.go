package token

import "sync"

// VerifierMetrics 验证器监控指标
type VerifierMetrics struct {
	TotalVerifications  int64
	LocalVerifications  int64
	RemoteVerifications int64
	CacheHits           int64
	CacheMisses         int64
	VerificationErrors  int64
	JWKSFetches         int64
	JWKSFetchErrors     int64
	IntrospectionCalls  int64
	IntrospectionErrors int64

	mu sync.RWMutex
}
