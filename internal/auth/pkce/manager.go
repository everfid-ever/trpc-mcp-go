package pkce

import (
	"sync"
	"time"
)

// 管理器
type Manager struct {
	mu          sync.RWMutex
	challenges  map[string]*Challenge
	config      *Config
	stats       *Stats
	stopCleanup chan struct{}
}

// 创建管理器
func NewManager(cfg *Config) *Manager {
	if cfg == nil {
		cfg = &Config{}
	}
	if cfg.ChallengeExpiry == 0 {
		cfg.ChallengeExpiry = 5 * time.Minute
	}
	if cfg.MaxChallenges == 0 {
		cfg.MaxChallenges = 10000
	}
	if cfg.VerifierLength == 0 {
		cfg.VerifierLength = 128
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Minute
	}
	return &Manager{
		challenges:  make(map[string]*Challenge),
		config:      cfg,
		stats:       &Stats{},
		stopCleanup: make(chan struct{}),
	}
}

// 生成挑战
func (m *Manager) GenerateChallenge(clientID string) (*Challenge, error) {
	if clientID == "" {
		return nil, &Error{Code: "invalid_client_id", Description: "client_id cannot be empty"}
	}
	m.mu.RLock()
	if len(m.challenges) >= m.config.MaxChallenges {
		m.mu.RUnlock()
		return nil, ErrTooManyChallenges
	}
	m.mu.RUnlock()
	verifier, err := GenerateSecureVerifier(m.config.VerifierLength)
	if err != nil {
		return nil, err
	}
	challenge := ComputeS256Challenge(verifier)
	now := time.Now()
	chal := &Challenge{
		Verifier:  verifier,
		Challenge: challenge,
		Method:    "S256",
		ClientID:  clientID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.config.ChallengeExpiry),
	}
	m.mu.Lock()
	m.challenges[challenge] = chal
	m.mu.Unlock()
	if m.config.EnableStats {
		m.updateStats(func(s *Stats) {
			s.ChallengesGenerated++
			s.ActiveChallenges++
		})
	}
	return chal, nil
}

// 验证挑战
func (m *Manager) VerifyChallenge(challenge, verifier, clientID string) error {
	if challenge == "" || verifier == "" || clientID == "" {
		return &Error{Code: "invalid_params", Description: "params must not be empty"}
	}
	if err := ValidateVerifier(verifier); err != nil {
		m.updateVerificationFailure()
		return err
	}
	m.mu.RLock()
	stored, exists := m.challenges[challenge]
	m.mu.RUnlock()
	if !exists {
		m.updateVerificationFailure()
		return ErrChallengeNotFound
	}
	if stored.ClientID != clientID {
		m.updateVerificationFailure()
		return ErrClientMismatch
	}
	if stored.Used {
		m.updateVerificationFailure()
		return ErrChallengeAlreadyUsed
	}
	if time.Now().After(stored.ExpiresAt) {
		m.mu.Lock()
		delete(m.challenges, challenge)
		m.mu.Unlock()
		m.updateVerificationFailure()
		return ErrChallengeExpired
	}
	if !VerifyS256Challenge(verifier, challenge) {
		m.updateVerificationFailure()
		return ErrVerificationFailed
	}
	// 标记已用
	m.mu.Lock()
	stored.Used = true
	stored.UsedAt = time.Now()
	m.mu.Unlock()
	if m.config.EnableStats {
		m.updateStats(func(s *Stats) {
			s.ChallengesVerified++
			s.ActiveChallenges--
		})
	}
	// 异步清理
	go func() {
		time.Sleep(time.Second)
		m.mu.Lock()
		delete(m.challenges, challenge)
		m.mu.Unlock()
	}()
	return nil
}

// 清理过期挑战
func (m *Manager) CleanupExpiredChallenges() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	count := 0
	for k, v := range m.challenges {
		if now.After(v.ExpiresAt) {
			delete(m.challenges, k)
			count++
		}
	}
	if m.config.EnableStats && count > 0 {
		m.stats.mu.Lock()
		m.stats.ExpiredChallenges += int64(count)
		m.stats.ActiveChallenges -= int64(count)
		m.stats.LastCleanup = now
		m.stats.mu.Unlock()
	}
	return count
}

// 定期清理
func (m *Manager) StartCleanup() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.CleanupExpiredChallenges()
		case <-m.stopCleanup:
			return
		}
	}
}

// 关闭管理器
func (m *Manager) Close() {
	close(m.stopCleanup)
	m.mu.Lock()
	m.challenges = make(map[string]*Challenge)
	m.mu.Unlock()
	if m.config.EnableStats {
		m.stats.mu.Lock()
		m.stats.ActiveChallenges = 0
		m.stats.mu.Unlock()
	}
}

// 统计辅助方法
func (m *Manager) updateStats(fn func(*Stats)) {
	m.stats.mu.Lock()
	fn(m.stats)
	m.stats.mu.Unlock()
}
func (m *Manager) updateVerificationFailure() {
	if m.config.EnableStats {
		m.updateStats(func(s *Stats) {
			s.VerificationFailures++
		})
	}
}
func (m *Manager) GetStats() *Stats {
	if !m.config.EnableStats {
		return nil
	}
	m.stats.mu.RLock()
	defer m.stats.mu.RUnlock()
	cpy := *m.stats
	return &cpy
}
func (m *Manager) GetActiveChallenges() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.challenges)
}
func (m *Manager) IsValidChallenge(challenge, clientID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	stored, exists := m.challenges[challenge]
	if !exists || stored.ClientID != clientID || stored.Used || time.Now().After(stored.ExpiresAt) {
		return false
	}
	return true
}
