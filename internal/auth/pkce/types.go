package pkce

import (
	"sync"
	"time"
)

type Config struct {
	ChallengeExpiry time.Duration
	MaxChallenges   int
	VerifierLength  int
	EnableStats     bool
	CleanupInterval time.Duration
}

type Challenge struct {
	Verifier  string
	Challenge string
	Method    string
	ClientID  string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
	UsedAt    time.Time
}

type Stats struct {
	mu                   sync.RWMutex
	ChallengesGenerated  int64
	ChallengesVerified   int64
	VerificationFailures int64
	ExpiredChallenges    int64
	ActiveChallenges     int64
	LastCleanup          time.Time
}
