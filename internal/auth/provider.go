package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	stdErr "errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/errors"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/pkce"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// AuthProvider 定义统一的认证提供者接口，支持多种 OAuth 2.1 实现
type AuthProvider interface {
	// VerifyToken 验证访问令牌的有效性
	VerifyToken(ctx context.Context, token string) (*TokenInfo, error)

	// GetAuthorizationURL 生成授权URL，支持PKCE增强
	GetAuthorizationURL(req *AuthorizationRequest) (string, error)

	// ExchangeToken 使用授权码交换访问令牌（必须验证PKCE）
	ExchangeToken(ctx context.Context, code string, req *TokenRequest) (*TokenResponse, error)

	// RefreshToken 使用刷新令牌获取新的访问令牌
	RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error)

	// RevokeToken 撤销访问令牌或刷新令牌
	RevokeToken(ctx context.Context, token string) error

	// GetServerMetadata 获取授权服务器元数据
	GetServerMetadata(ctx context.Context) (*ServerMetadata, error)

	// ValidateToken 验证令牌并返回详细信息
	ValidateToken(ctx context.Context, token string, requiredScopes []string) (*TokenInfo, error)

	// GenerateAuthorizationCode 生成授权码（服务端用）
	GenerateAuthorizationCode(ctx context.Context, req *AuthCodeRequest) (string, error)
}

// TokenInfo 包含验证后的令牌信息
type TokenInfo struct {
	Subject   string                 `json:"sub"`
	Audience  []string               `json:"aud"`
	Scopes    []string               `json:"scope"`
	ClientID  string                 `json:"client_id"`
	ExpiresAt time.Time              `json:"exp"`
	IssuedAt  time.Time              `json:"iat"`
	Active    bool                   `json:"active"`
	TokenType string                 `json:"token_type"`
	Claims    map[string]interface{} `json:"claims,omitempty"`
	TokenID   string                 `json:"jti,omitempty"` // JWT ID
	NotBefore time.Time              `json:"nbf,omitempty"`
	Issuer    string                 `json:"iss,omitempty"`
}

// AuthCodeRequest 授权码生成请求
type AuthCodeRequest struct {
	ClientID        string    `json:"client_id"`
	UserID          string    `json:"user_id"`
	Scopes          []string  `json:"scopes"`
	RedirectURI     string    `json:"redirect_uri"`
	CodeChallenge   string    `json:"code_challenge"`
	ChallengeMethod string    `json:"code_challenge_method"`
	State           string    `json:"state,omitempty"`
	ExpiresAt       time.Time `json:"expires_at"`
}

// AuthorizationCode 授权码存储结构（以 code 为 key）
type AuthorizationCode struct {
	Code            string    `json:"code"`
	ClientID        string    `json:"client_id"`
	UserID          string    `json:"user_id"`
	Scopes          []string  `json:"scopes"`
	RedirectURI     string    `json:"redirect_uri"`
	CodeChallenge   string    `json:"code_challenge"`
	ChallengeMethod string    `json:"code_challenge_method"`
	State           string    `json:"state,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Used            bool      `json:"used"`    // 防止重复使用
	UsedAt          time.Time `json:"used_at"` // 使用时间
}

// AuthorizationRequest 授权请求参数
type AuthorizationRequest struct {
	ClientID            string            `json:"client_id"`
	RedirectURI         string            `json:"redirect_uri"`
	Scopes              []string          `json:"scope"`
	State               string            `json:"state"`
	CodeChallenge       string            `json:"code_challenge"`
	CodeChallengeMethod string            `json:"code_challenge_method"`
	ResponseType        string            `json:"response_type"`
	AdditionalParams    map[string]string `json:"additional_params,omitempty"`
}

// TokenRequest 令牌交换请求参数
type TokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURI  string `json:"redirect_uri"`
	GrantType    string `json:"grant_type"`
	CodeVerifier string `json:"code_verifier"` // PKCE 验证器
}

// TokenResponse 令牌响应
type TokenResponse struct {
	AccessToken    string                 `json:"access_token"`
	TokenType      string                 `json:"token_type"`
	ExpiresIn      int64                  `json:"expires_in"`
	RefreshToken   string                 `json:"refresh_token,omitempty"`
	Scope          string                 `json:"scope,omitempty"`
	TokenID        string                 `json:"jti,omitempty"`
	AdditionalData map[string]interface{} `json:"additional_data,omitempty"`
}

// ServerMetadata 授权服务器元数据
type ServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	JWKSUri                           string   `json:"jwks_uri,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// TokenManager 令牌管理器 - 负责 JWT 生成和验证
type TokenManager struct {
	// RSA 密钥对
	privateKey      *rsa.PrivateKey
	publicKey       *rsa.PublicKey
	signingMethod   jwt.SigningMethod
	issuer          string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration

	// 令牌存储
	mu            sync.RWMutex
	accessTokens  map[string]*TokenInfo
	refreshTokens map[string]*RefreshTokenInfo
	signingKey    interface{}
}

// RefreshTokenInfo 刷新令牌信息
type RefreshTokenInfo struct {
	RefreshToken  string    `json:"refresh_token_id"`
	AccessTokenID string    `json:"access_token_id"`
	UserID        string    `json:"user_id"`
	ClientID      string    `json:"client_id"`
	Scopes        []string  `json:"scopes"`
	ExpiresAt     time.Time `json:"expires_at"`
	CreatedAt     time.Time `json:"created_at"`
	Used          bool      `json:"used"`
}

// NewTokenManager 创建令牌管理器
func NewTokenManager(issuer string, signingKey []byte) *TokenManager {
	tm := &TokenManager{
		issuer:          issuer,
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		accessTokens:    make(map[string]*TokenInfo),
		refreshTokens:   make(map[string]*RefreshTokenInfo),
	}

	// 设置签名密钥和方法
	if signingKey != nil {
		tm.signingKey = signingKey
		tm.signingMethod = jwt.SigningMethodHS256
	} else {
		// 不默认设为 RS256，必须调用 SetRSAKeys 或 SetHMAC 来配置签名方法
		tm.signingMethod = nil
	}

	return tm
}

func (tm *TokenManager) SetRSAKeys(privateKey *rsa.PrivateKey) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.privateKey = privateKey
	tm.publicKey = &privateKey.PublicKey
	tm.signingMethod = jwt.SigningMethodRS256
}

// GenerateAccessToken 生成访问令牌
func (tm *TokenManager) GenerateAccessToken(userID, clientID string, scopes []string) (*TokenResponse, error) {
	if tm.signingMethod == nil {
		return nil, fmt.Errorf("signing method not configured")
	}

	now := time.Now()
	tokenID := uuid.New().String()

	// 创建 JWT 声明
	claims := jwt.MapClaims{
		"sub":        userID,
		"aud":        []string{clientID},
		"iss":        tm.issuer,
		"iat":        now.Unix(),
		"exp":        now.Add(tm.AccessTokenTTL).Unix(),
		"nbf":        now.Unix(),
		"jti":        tokenID,
		"scope":      strings.Join(scopes, " "),
		"client_id":  clientID,
		"token_type": "access_token",
	}

	// 创建并签名 JWT
	token := jwt.NewWithClaims(tm.signingMethod, claims)

	var tokenString string
	var err error

	// 根据签名方法选择密钥并签名
	switch tm.signingMethod {
	case jwt.SigningMethodRS256:
		if tm.privateKey == nil {
			return nil, fmt.Errorf("RSA key not configured")
		}
		tokenString, err = token.SignedString(tm.privateKey)
	case jwt.SigningMethodHS256:
		if tm.signingKey == nil {
			return nil, fmt.Errorf("HMAC signing key not configured")
		}
		tokenString, err = token.SignedString(tm.signingKey)
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", tm.signingMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// 创建刷新令牌
	refreshTokenID := uuid.New().String()
	refreshTokenInfo := &RefreshTokenInfo{
		RefreshToken:  refreshTokenID,
		AccessTokenID: tokenID,
		UserID:        userID,
		ClientID:      clientID,
		Scopes:        scopes,
		ExpiresAt:     now.Add(tm.RefreshTokenTTL),
		CreatedAt:     now,
		Used:          false,
	}

	// 存储令牌信息
	tokenInfo := &TokenInfo{
		Subject:   userID,
		Audience:  []string{clientID},
		Scopes:    scopes,
		ClientID:  clientID,
		ExpiresAt: now.Add(tm.AccessTokenTTL),
		IssuedAt:  now,
		Active:    true,
		TokenType: "Bearer",
		TokenID:   tokenID,
		NotBefore: now,
		Issuer:    tm.issuer,
	}

	tm.mu.Lock()
	tm.accessTokens[tokenID] = tokenInfo
	tm.refreshTokens[refreshTokenID] = refreshTokenInfo
	tm.mu.Unlock()

	return &TokenResponse{
		AccessToken:  tokenString,
		TokenType:    "Bearer",
		ExpiresIn:    int64(tm.AccessTokenTTL.Seconds()),
		RefreshToken: refreshTokenID,
		Scope:        strings.Join(scopes, " "),
		TokenID:      tokenID,
	}, nil
}

// ValidateAccessToken 验证访问令牌
func (tm *TokenManager) ValidateAccessToken(tokenString string) (*TokenInfo, error) {
	if tokenString == "" {
		return nil, errors.ErrInvalidToken
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA:
			return tm.publicKey, nil
		case *jwt.SigningMethodHMAC:
			return tm.signingKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		if stdErr.Is(err, jwt.ErrTokenExpired) {
			return nil, errors.ErrExpiredToken
		}
		return nil, &errors.AuthError{
			Code:        "invalid_token",
			Description: err.Error(),
			HTTPStatus:  401,
		}
	}

	if !token.Valid {
		return nil, errors.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.ErrInvalidToken
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, errors.ErrInvalidToken
	}

	tm.mu.RLock()
	stored, exists := tm.accessTokens[jti]
	tm.mu.RUnlock()
	if !exists {
		return nil, errors.ErrInvalidToken
	}

	// 双重校验过期时间
	if expRaw, has := claims["exp"]; has {
		switch v := expRaw.(type) {
		case float64:
			if time.Now().After(time.Unix(int64(v), 0)) {
				tm.mu.Lock()
				delete(tm.accessTokens, jti)
				tm.mu.Unlock()
				return nil, errors.ErrExpiredToken
			}
		case json.Number:
			if i, e := v.Int64(); e == nil && time.Now().After(time.Unix(i, 0)) {
				tm.mu.Lock()
				delete(tm.accessTokens, jti)
				tm.mu.Unlock()
				return nil, errors.ErrExpiredToken
			}
		case int64:
			if time.Now().After(time.Unix(v, 0)) {
				tm.mu.Lock()
				delete(tm.accessTokens, jti)
				tm.mu.Unlock()
				return nil, errors.ErrExpiredToken
			}
		case string:
			if i, e := strconv.ParseInt(v, 10, 64); e == nil {
				if time.Now().After(time.Unix(i, 0)) {
					tm.mu.Lock()
					delete(tm.accessTokens, jti)
					tm.mu.Unlock()
					return nil, errors.ErrExpiredToken
				}
			}
		default:
		}
	} else if time.Now().After(stored.ExpiresAt) {
		tm.mu.Lock()
		delete(tm.accessTokens, jti)
		tm.mu.Unlock()
		return nil, errors.ErrExpiredToken
	}

	return stored, nil
}

// ValidateAccessTokenFromRequest OAuth 2.1 兼容的令牌验证
func (tm *TokenManager) ValidateAccessTokenFromRequest(r *http.Request) (*TokenInfo, error) {
	// OAuth 2.1: 禁止在查询字符串中使用 Bearer 令牌
	if r.URL.Query().Get("access_token") != "" {
		return nil, &errors.AuthError{
			Code:        "invalid_request",
			Description: "OAuth 2.1 prohibits access tokens in query parameters",
			HTTPStatus:  400,
		}
	}

	// 从 Authorization header 提取令牌
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			return tm.ValidateAccessToken(parts[1])
		}
	}

	// 检查 POST 请求体中的令牌（仅限表单编码）
	if r.Method == "POST" && strings.Contains(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err == nil {
			if token := r.Form.Get("access_token"); token != "" {
				return tm.ValidateAccessToken(token)
			}
		}
	}

	return nil, &errors.AuthError{
		Code:        "invalid_request",
		Description: "Missing or invalid access token",
		HTTPStatus:  401,
	}
}

// RevokeRawToken accepts a raw token string (JWT or refresh token) and revokes it
func (tm *TokenManager) RevokeRawToken(raw string) error {
	//RFC7009: If the token is empty or malformed,
	//its existence should not be disclosed and nil should be returned directly.
	if strings.TrimSpace(raw) == "" {
		return nil
	}

	// Try parse as JWT without requiring validation of claims (we only need jti)
	parsed, _, err := new(jwt.Parser).ParseUnverified(raw, jwt.MapClaims{})
	if err == nil && parsed != nil {
		if claims, ok := parsed.Claims.(jwt.MapClaims); ok {
			if jti, ok := claims["jti"].(string); ok && jti != "" {
				tm.mu.Lock()
				delete(tm.accessTokens, jti)
				// 同时删除关联的 refresh token
				for rid, rinfo := range tm.refreshTokens {
					if rinfo != nil && rinfo.AccessTokenID == jti {
						delete(tm.refreshTokens, rid)
					}
				}
				tm.mu.Unlock()
				return nil
			}
		}
	}

	//If it cannot be parsed as a JWT, then the raw is treated as the refresh token id
	tm.mu.Lock()
	if rinfo, exists := tm.refreshTokens[raw]; exists {
		// Delete refresh token
		delete(tm.refreshTokens, raw)
		// Delete the associated access token
		if rinfo.AccessTokenID != "" {
			delete(tm.accessTokens, rinfo.AccessTokenID)
		}
	}
	tm.mu.Unlock()

	return nil
}

// 兼容旧名：保持 RevokeToken 方法但内部委托
func (tm *TokenManager) RevokeToken(tokenID string) error {
	// 后向兼容：允许传入 jti 或原始 token
	return tm.RevokeRawToken(tokenID)
}

// DefaultAuthProvider 完整实现的认证提供者
type DefaultAuthProvider struct {
	Config       *AuthConfig
	TokenManager *TokenManager

	// 存储结构重新设计：以 code 为 key
	mu        sync.RWMutex
	AuthCodes map[string]*AuthorizationCode // code
	// -> AuthorizationCode
	PkceManager *pkce.Manager // 使用完整的PKCE管理器
}

// AuthConfig 认证配置
type AuthConfig struct {
	ServerURL       string        `json:"server_url"`
	ClientID        string        `json:"client_id"`
	ClientSecret    string        `json:"client_secret,omitempty"`
	RedirectURI     string        `json:"redirect_uri"`
	Timeout         time.Duration `json:"timeout"`
	SigningKey      []byte        `json:"signing_key"`
	CodeTTL         time.Duration `json:"code_ttl"` // 授权码存活时间
	AccessTokenTTL  time.Duration `json:"access_token_ttl"`
	RefreshTokenTTL time.Duration `json:"refresh_token_ttl"`
	PKCEConfig      *pkce.Config  `json:"pkce_config,omitempty"` // PKCE配置
}

// NewDefaultAuthProvider 创建默认认证提供者
func NewDefaultAuthProvider(config *AuthConfig) *DefaultAuthProvider {
	// 设置默认值
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.CodeTTL == 0 {
		config.CodeTTL = 10 * time.Minute // 授权码10分钟过期
	}
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = time.Hour
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 24 * time.Hour
	}
	if len(config.SigningKey) == 0 {
		config.SigningKey = []byte("default-signing-key-change-in-production")
	}

	tokenManager := NewTokenManager(config.ServerURL, config.SigningKey)
	tokenManager.AccessTokenTTL = config.AccessTokenTTL
	tokenManager.RefreshTokenTTL = config.RefreshTokenTTL

	// 创建PKCE管理器
	pkceConfig := config.PKCEConfig
	if pkceConfig == nil {
		// 使用默认PKCE配置
		pkceConfig = &pkce.Config{
			ChallengeExpiry: 5 * time.Minute,
			MaxChallenges:   10000,
			VerifierLength:  128,
			EnableStats:     true,
			CleanupInterval: time.Minute,
		}
	}

	return &DefaultAuthProvider{
		Config:       config,
		TokenManager: tokenManager,
		AuthCodes:    make(map[string]*AuthorizationCode),
		PkceManager:  pkce.NewManager(pkceConfig),
	}
}

// VerifyToken 实现接口
func (p *DefaultAuthProvider) VerifyToken(ctx context.Context, token string) (*TokenInfo, error) {
	return p.TokenManager.ValidateAccessToken(token)
}

// ValidateToken 实现接口 - 支持作用域验证
func (p *DefaultAuthProvider) ValidateToken(ctx context.Context, token string, requiredScopes []string) (*TokenInfo, error) {
	tokenInfo, err := p.TokenManager.ValidateAccessToken(token)
	if err != nil {
		return nil, err
	}

	// 验证作用域
	if len(requiredScopes) > 0 {
		if !p.hasRequiredScopes(tokenInfo.Scopes, requiredScopes) {
			return nil, errors.ErrInsufficientScope
		}
	}

	return tokenInfo, nil
}

// hasRequiredScopes 检查是否拥有必需的作用域
func (p *DefaultAuthProvider) hasRequiredScopes(tokenScopes, requiredScopes []string) bool {
	scopeMap := make(map[string]bool)
	for _, scope := range tokenScopes {
		scopeMap[scope] = true
	}

	for _, required := range requiredScopes {
		if !scopeMap[required] {
			return false
		}
	}
	return true
}

// GenerateAuthorizationCode 生成授权码
func (p *DefaultAuthProvider) GenerateAuthorizationCode(ctx context.Context, req *AuthCodeRequest) (string, error) {
	// 生成唯一授权码
	code := uuid.New().String()

	// 设置过期时间
	expiresAt := req.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(p.Config.CodeTTL)
	}

	authCode := &AuthorizationCode{
		Code:            code,
		ClientID:        req.ClientID,
		UserID:          req.UserID,
		Scopes:          req.Scopes,
		RedirectURI:     req.RedirectURI,
		CodeChallenge:   req.CodeChallenge,
		ChallengeMethod: req.ChallengeMethod,
		State:           req.State,
		CreatedAt:       time.Now(),
		ExpiresAt:       expiresAt,
		Used:            false,
	}

	// 存储授权码（以 code 为 key）
	p.mu.Lock()
	p.AuthCodes[code] = authCode
	p.mu.Unlock()

	return code, nil
}

// GetAuthorizationURL 实现接口
func (p *DefaultAuthProvider) GetAuthorizationURL(req *AuthorizationRequest) (string, error) {
	if req.ClientID == "" {
		return "", errors.ErrInvalidRequest
	}

	// OAuth 2.1 强制要求 PKCE
	if req.CodeChallenge == "" || req.CodeChallengeMethod != "S256" {
		return "", &errors.AuthError{
			Code:        "invalid_request",
			Description: "OAuth 2.1 requires PKCE with S256 method",
		}
	}

	baseURL := p.Config.ServerURL + "/authorize"
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", req.ClientID)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("state", req.State)
	params.Set("code_challenge", req.CodeChallenge)
	params.Set("code_challenge_method", req.CodeChallengeMethod)

	if len(req.Scopes) > 0 {
		params.Set("scope", strings.Join(req.Scopes, " "))
	}

	for k, v := range req.AdditionalParams {
		params.Set(k, v)
	}

	return baseURL + "?" + params.Encode(), nil
}

// ExchangeToken 实现接口 - 使用PKCE管理器进行验证
func (p *DefaultAuthProvider) ExchangeToken(ctx context.Context, code string, req *TokenRequest) (*TokenResponse, error) {
	if code == "" || req.CodeVerifier == "" {
		return nil, errors.ErrInvalidRequest
	}

	// 查找授权码
	p.mu.Lock()
	authCode, exists := p.AuthCodes[code]
	if !exists {
		p.mu.Unlock()
		return nil, errors.ErrInvalidGrant
	}

	// 检查授权码是否已使用
	if authCode.Used {
		p.mu.Unlock()
		return nil, errors.ErrCodeUsed
	}

	// 检查授权码是否过期
	if time.Now().After(authCode.ExpiresAt) {
		delete(p.AuthCodes, code)
		p.mu.Unlock()
		return nil, errors.ErrCodeExpired
	}

	// 标记授权码为已使用（防止重复使用）
	authCode.Used = true
	authCode.UsedAt = time.Now()
	p.mu.Unlock()

	// 验证客户端ID
	if authCode.ClientID != req.ClientID {
		return nil, errors.ErrInvalidClient
	}

	// 验证重定向URI
	if authCode.RedirectURI != req.RedirectURI {
		return nil, errors.ErrInvalidGrant
	}

	// 使用PKCE管理器验证挑战
	if err := p.PkceManager.VerifyChallenge(authCode.CodeChallenge, req.CodeVerifier, req.ClientID); err != nil {
		// 将PKCEError转换为AuthError
		if pkceErr, ok := err.(*pkce.Error); ok {
			return nil, &errors.AuthError{
				Code:        "invalid_grant",
				Description: pkceErr.Description,
				HTTPStatus:  400,
			}
		}
		return nil, err
	}

	// 生成访问令牌
	tokenResponse, err := p.TokenManager.GenerateAccessToken(
		authCode.UserID,
		authCode.ClientID,
		authCode.Scopes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	// 清理已使用的授权码
	p.mu.Lock()
	delete(p.AuthCodes, code)
	p.mu.Unlock()

	return tokenResponse, nil
}

// RefreshToken 实现接口
func (p *DefaultAuthProvider) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	p.TokenManager.mu.RLock()
	refreshInfo, exists := p.TokenManager.refreshTokens[refreshToken]
	p.TokenManager.mu.RUnlock()

	if !exists {
		return nil, errors.ErrInvalidGrant
	}

	// 检查是否已使用
	if refreshInfo.Used {
		return nil, errors.ErrInvalidGrant
	}

	// 检查过期时间
	if time.Now().After(refreshInfo.ExpiresAt) {
		p.TokenManager.mu.Lock()
		delete(p.TokenManager.refreshTokens, refreshToken)
		p.TokenManager.mu.Unlock()
		return nil, errors.ErrInvalidGrant
	}

	// 标记旧刷新令牌为已使用
	p.TokenManager.mu.Lock()
	refreshInfo.Used = true
	p.TokenManager.mu.Unlock()

	// 在刷新前撤销旧的 access token
	if refreshInfo.AccessTokenID != "" {
		_ = p.TokenManager.refreshTokens[refreshInfo.AccessTokenID]
	}

	// 生成新的访问令牌
	return p.TokenManager.GenerateAccessToken(
		refreshInfo.UserID,
		refreshInfo.ClientID,
		refreshInfo.Scopes,
	)
}

// RevokeAllTokensForClient 撤销该客户端的所有 access/refresh token
func (tm *TokenManager) RevokeAllTokensForClient(clientID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	for tokenID, tokenInfo := range tm.accessTokens {
		if tokenInfo.ClientID == clientID {
			delete(tm.accessTokens, tokenID)
		}
	}
	for tokenID, tokenInfo := range tm.refreshTokens {
		if tokenInfo.ClientID == clientID {
			delete(tm.refreshTokens, tokenID)
		}
	}
	return nil
}

// RevokeToken 实现接口
func (p *DefaultAuthProvider) RevokeToken(ctx context.Context, token string) error {
	// 尝试撤销访问令牌或刷新令牌
	return p.TokenManager.RevokeToken(token)
}

// GetServerMetadata 实现接口
func (p *DefaultAuthProvider) GetServerMetadata(ctx context.Context) (*ServerMetadata, error) {
	return &ServerMetadata{
		Issuer:                            p.Config.ServerURL,
		AuthorizationEndpoint:             p.Config.ServerURL + "/authorize",
		TokenEndpoint:                     p.Config.ServerURL + "/token",
		RevocationEndpoint:                p.Config.ServerURL + "/revoke",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}, nil
}

// 清理方法
func (p *DefaultAuthProvider) CleanupExpiredCodes() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	cleanedCount := 0

	for code, authCode := range p.AuthCodes {
		if now.After(authCode.ExpiresAt) {
			delete(p.AuthCodes, code)
			cleanedCount++
		}
	}

	return cleanedCount
}

func (tm *TokenManager) CleanupExpiredTokens() int {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	now := time.Now()
	cleanedCount := 0

	//清理过期的访问令牌
	for tokenID, tokenInfo := range tm.accessTokens {
		if now.After(tokenInfo.ExpiresAt) {
			// 删除 access token
			delete(tm.accessTokens, tokenID)
			cleanedCount++
			// 同时删除与该 access token 关联的 refresh token
			for rid, rinfo := range tm.refreshTokens {
				if rinfo != nil && rinfo.AccessTokenID == tokenID {
					delete(tm.refreshTokens, rid)
					cleanedCount++
				}
			}
		}
	}

	// 清理过期的刷新令牌
	for refreshID, refreshInfo := range tm.refreshTokens {
		if now.After(refreshInfo.ExpiresAt) {
			delete(tm.refreshTokens, refreshID)
			cleanedCount++
		}
	}

	return cleanedCount
}

func (p *DefaultAuthProvider) GetPKCEStats() *pkce.Stats {
	if p.PkceManager == nil {
		return nil
	}
	return p.PkceManager.GetStats() // 只暴露需要的信息
}

func (p *DefaultAuthProvider) CleanupExpiredPKCEChallenges() int {
	if p.PkceManager == nil {
		return 0
	}
	return p.PkceManager.CleanupExpiredChallenges()
}

// GeneratePKCEChallenge 生成PKCE挑战
func (p *DefaultAuthProvider) GeneratePKCEChallenge(clientID string) (*pkce.Challenge, error) {
	return p.PkceManager.GenerateChallenge(clientID)
}
