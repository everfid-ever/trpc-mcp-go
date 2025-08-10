package token

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Token 令牌信息
type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Scope        string    `json:"scope,omitempty"`
	TokenID      string    `json:"token_id,omitempty"`

	// 元数据
	IssuedAt time.Time `json:"issued_at"`
	ClientID string    `json:"client_id"`
	UserID   string    `json:"user_id,omitempty"`
}

// TokenStore 令牌存储接口
type TokenStore interface {
	// StoreToken 存储令牌
	StoreToken(ctx context.Context, token *Token) error

	// GetToken 获取令牌
	GetToken(ctx context.Context, tokenID string) (*Token, error)

	// GetTokenByClientID 根据客户端ID获取最新令牌
	GetTokenByClientID(ctx context.Context, clientID string) (*Token, error)

	// UpdateToken 更新令牌
	UpdateToken(ctx context.Context, token *Token) error

	// DeleteToken 删除令牌
	DeleteToken(ctx context.Context, tokenID string) error

	// ListTokens 列出所有令牌
	ListTokens(ctx context.Context) ([]*Token, error)
}

// InMemoryTokenStore 内存令牌存储实现
type InMemoryTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*Token
}

// NewInMemoryTokenStore 创建内存令牌存储
func NewInMemoryTokenStore() *InMemoryTokenStore {
	return &InMemoryTokenStore{
		tokens: make(map[string]*Token),
	}
}

func (s *InMemoryTokenStore) StoreToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.TokenID] = token
	return nil
}

func (s *InMemoryTokenStore) GetToken(ctx context.Context, tokenID string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	token, exists := s.tokens[tokenID]
	if !exists {
		return nil, fmt.Errorf("token not found")
	}
	return token, nil
}

func (s *InMemoryTokenStore) GetTokenByClientID(ctx context.Context, clientID string) (*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var latest *Token
	for _, token := range s.tokens {
		if token.ClientID == clientID {
			if latest == nil || token.IssuedAt.After(latest.IssuedAt) {
				latest = token
			}
		}
	}

	if latest == nil {
		return nil, fmt.Errorf("no token found for client")
	}
	return latest, nil
}

func (s *InMemoryTokenStore) UpdateToken(ctx context.Context, token *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[token.TokenID] = token
	return nil
}

func (s *InMemoryTokenStore) DeleteToken(ctx context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, tokenID)
	return nil
}

func (s *InMemoryTokenStore) ListTokens(ctx context.Context) ([]*Token, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tokens := make([]*Token, 0, len(s.tokens))
	for _, token := range s.tokens {
		tokens = append(tokens, token)
	}
	return tokens, nil
}
