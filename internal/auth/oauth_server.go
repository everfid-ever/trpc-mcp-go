package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/errors"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/pkce"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/store"
)

// OAuthServerProvider 实现符合 MCP 2025-03-26 规范的 OAuth 2.1 服务器
type OAuthServerProvider struct {
	config       *ServerConfig
	clientStore  store.ClientStore
	tokenManager *TokenManager
	keyManager   *KeyManager
	scopeManager *ScopeManager
	pkceManager  *pkce.Manager

	// HTTP 路由器
	mux *http.ServeMux

	// 并发安全
	mu sync.RWMutex

	// 共享的 AuthProvider（保持授权码/交换的一致性）
	authProvider *DefaultAuthProvider

	// registration token -> clientID 映射（用于 RFC7591 后续查询/更新）
	registrationTokens map[string]string
}

// ServerConfig OAuth 服务器配置
type ServerConfig struct {
	// 基础配置
	Issuer  string `json:"issuer"`
	BaseURL string `json:"base_url"`

	OAuth21StrictMode     bool `json:"oauth21_strict_mode"`      // 是否启用 OAuth 2.1 严格模式
	AllowQueryStringToken bool `json:"allow_query_string_token"` // OAuth 2.1 必须为 false

	// 端点路径
	AuthorizeEndpoint     string `json:"authorize_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
	JWKSEndpoint          string `json:"jwks_endpoint"`
	MetadataEndpoint      string `json:"metadata_endpoint"`

	// 令牌配置
	AccessTokenTTL  time.Duration `json:"access_token_ttl"`
	RefreshTokenTTL time.Duration `json:"refresh_token_ttl"`
	AuthCodeTTL     time.Duration `json:"auth_code_ttl"`

	// 安全配置
	RequirePKCE          bool     `json:"require_pkce"` // OAuth 2.1 强制要求
	AllowedGrantTypes    []string `json:"allowed_grant_types"`
	AllowedResponseTypes []string `json:"allowed_response_types"`
	AllowedScopes        []string `json:"allowed_scopes"`

	// 密钥配置
	RSAPrivateKey *rsa.PrivateKey `json:"-"`
	RSAPublicKey  *rsa.PublicKey  `json:"-"`

	// 用户验证回调
	UserAuthenticator UserAuthenticator `json:"-"`
	UserAuthorizer    UserAuthorizer    `json:"-"`
}

// UserAuthenticator 用户身份验证接口
type UserAuthenticator interface {
	// AuthenticateUser 验证用户身份
	AuthenticateUser(ctx context.Context, req *http.Request) (*UserInfo, error)
}

// UserAuthorizer 用户授权接口
type UserAuthorizer interface {
	// AuthorizeUser 检查用户是否授权访问指定范围
	AuthorizeUser(ctx context.Context, userID, clientID string, scopes []string) (bool, error)
}

// UserInfo 用户信息
type UserInfo struct {
	UserID   string                 `json:"user_id"`
	Username string                 `json:"username"`
	Email    string                 `json:"email,omitempty"`
	Claims   map[string]interface{} `json:"claims,omitempty"`
}

// KeyManager 密钥管理器
type KeyManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	mu         sync.RWMutex
}

// NewKeyManager 创建密钥管理器
func NewKeyManager(privateKey *rsa.PrivateKey) *KeyManager {
	if privateKey == nil {
		// 如果没有提供私钥, 则生成一个
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(fmt.Sprintf("failed to generate rsa key: %v", err))
		}
		privateKey = pk
	}

	// 从私钥中提取公钥
	publicKey := &privateKey.PublicKey

	return &KeyManager{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      generateKeyID(publicKey), // 实现一个生成 keyID 的函数
		mu:         sync.RWMutex{},
	}
}

// generateKeyID 生成基于公钥 SHA-256 哈希的 Key ID (kid)
func generateKeyID(publicKey *rsa.PublicKey) string {
	// 1. 将公钥序列化为 ASN.1 DER 编码
	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		// 如果序列化失败，返回一个随机 ID 作为后备
		return "fallback-" + uuid.New().String()
	}

	// 2. 计算 SHA-256 哈希
	hash := sha256.Sum256(pubBytes)

	// 3. 使用 Base64URL 编码（无填充）生成 kid
	// Base64URL 编码是 JWT/JWK 标准推荐的
	kid := base64.RawURLEncoding.EncodeToString(hash[:])
	return kid
}

// GetJWKS 返回 JWKS (JSON Web Key Set)
func (km *KeyManager) GetJWKS() map[string]interface{} {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// 正确提取并编码 n 和 e
	n := km.publicKey.N
	e := big.NewInt(int64(km.publicKey.E))

	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": km.keyID, // 使用生成的 kid
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(n.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(e.Bytes()),
	}

	return map[string]interface{}{
		"keys": []map[string]interface{}{jwk},
	}
}

// ScopeManager 作用域管理器
type ScopeManager struct {
	scopes map[string]*ScopeDefinition
	mu     sync.RWMutex
}

// ScopeDefinition 作用域定义
type ScopeDefinition struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Required    bool   `json:"required"`  // 是否为必需作用域
	Sensitive   bool   `json:"sensitive"` // 是否为敏感作用域
}

// NewScopeManager 创建作用域管理器
func NewScopeManager() *ScopeManager {
	sm := &ScopeManager{
		scopes: make(map[string]*ScopeDefinition),
	}

	// 注册默认作用域
	sm.RegisterScope("read", "Read access", false, false)
	sm.RegisterScope("write", "Write access", false, false)
	sm.RegisterScope("admin", "Administrative access", false, true)

	return sm
}

// RegisterScope 注册作用域
func (sm *ScopeManager) RegisterScope(name, description string, required, sensitive bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.scopes[name] = &ScopeDefinition{
		Name:        name,
		Description: description,
		Required:    required,
		Sensitive:   sensitive,
	}
}

// ValidateScopes 验证作用域
func (sm *ScopeManager) ValidateScopes(requestedScopes []string) ([]string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var validScopes []string
	for _, scope := range requestedScopes {
		if def, exists := sm.scopes[scope]; exists {
			validScopes = append(validScopes, def.Name)
		} else {
			return nil, &errors.AuthError{
				Code:        "invalid_scope",
				Description: fmt.Sprintf("Unknown scope: %s", scope),
				HTTPStatus:  400,
			}
		}
	}

	return validScopes, nil
}

// SimpleInMemoryClientStore 内存客户端存储实现（兼容旧接口）
type SimpleInMemoryClientStore struct {
	clients map[string]*store.OAuthClient
	mu      sync.RWMutex
}

// NewSimpleInMemoryClientStore 创建内存客户端存储
func NewSimpleInMemoryClientStore() *SimpleInMemoryClientStore {
	return &SimpleInMemoryClientStore{
		clients: make(map[string]*store.OAuthClient),
	}
}

// GetClient 实现旧的 ClientStore 接口
func (s *SimpleInMemoryClientStore) GetClient(ctx context.Context, clientID string) (*store.OAuthClient, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return nil, errors.ErrInvalidClient
	}

	return client, nil
}

// StoreClient 实现旧的 ClientStore 接口
func (s *SimpleInMemoryClientStore) StoreClient(ctx context.Context, client *store.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.clients[client.ClientID] = client
	return nil
}

// UpdateClient 实现旧的 ClientStore 接口
func (s *SimpleInMemoryClientStore) UpdateClient(ctx context.Context, clientID string, client *store.OAuthClient) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[clientID]; !exists {
		return errors.ErrInvalidClient
	}

	s.clients[clientID] = client
	return nil
}

// DeleteClient 实现旧的 ClientStore 接口
func (s *SimpleInMemoryClientStore) DeleteClient(ctx context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.clients, clientID)
	return nil
}

// ValidateClientCredentials 实现旧的 ClientStore 接口
func (s *SimpleInMemoryClientStore) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*store.OAuthClient, error) {
	client, err := s.GetClient(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// 验证客户端密钥
	if client.ClientSecret != "" && client.ClientSecret != clientSecret {
		return nil, errors.ErrInvalidClient
	}

	return client, nil
}

// ClientStore 接口方法（委托给旧方法）
func (s *SimpleInMemoryClientStore) Create(ctx context.Context, client *store.OAuthClient) error {
	return s.StoreClient(ctx, client)
}

func (s *SimpleInMemoryClientStore) GetByID(ctx context.Context, clientID string) (*store.OAuthClient, error) {
	return s.GetClient(ctx, clientID)
}

func (s *SimpleInMemoryClientStore) Update(ctx context.Context, client *store.OAuthClient) error {
	return s.UpdateClient(ctx, client.ClientID, client)
}

func (s *SimpleInMemoryClientStore) Delete(ctx context.Context, clientID string) error {
	return s.DeleteClient(ctx, clientID)
}

func (s *SimpleInMemoryClientStore) List(ctx context.Context, offset, limit int) ([]*store.OAuthClient, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	total := len(s.clients)
	clients := make([]*store.OAuthClient, 0, limit)

	i := 0
	for _, client := range s.clients {
		if i >= offset && len(clients) < limit {
			clients = append(clients, client)
		}
		i++
	}

	return clients, total, nil
}

func (s *SimpleInMemoryClientStore) GetByCredentials(ctx context.Context, clientID, clientSecret string) (*store.OAuthClient, error) {
	return s.ValidateClientCredentials(ctx, clientID, clientSecret)
}

func (s *SimpleInMemoryClientStore) CleanupExpired(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0

	for clientID, client := range s.clients {
		if client.ExpiresAt != nil && client.ExpiresAt.Before(now) {
			delete(s.clients, clientID)
			count++
		}
	}

	return count, nil
}

func (s *SimpleInMemoryClientStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = make(map[string]*store.OAuthClient)
	return nil
}

// NewOAuthServerProvider 创建 OAuth 服务器提供者
func NewOAuthServerProvider(config *ServerConfig) (*OAuthServerProvider, error) {
	// 设置默认值
	if config.AccessTokenTTL == 0 {
		config.AccessTokenTTL = time.Hour
	}
	if config.RefreshTokenTTL == 0 {
		config.RefreshTokenTTL = 24 * time.Hour
	}
	if config.AuthCodeTTL == 0 {
		config.AuthCodeTTL = 10 * time.Minute
	}

	// OAuth 2.1 强制要求
	config.RequirePKCE = true
	config.OAuth21StrictMode = true
	config.AllowQueryStringToken = false // OAuth 2.1 要求

	if len(config.AllowedGrantTypes) == 0 {
		config.AllowedGrantTypes = []string{"authorization_code", "client_credentials", "refresh_token"}
	}
	if len(config.AllowedResponseTypes) == 0 {
		config.AllowedResponseTypes = []string{"code"} // OAuth 2.1 禁用 implicit
	}

	// 设置默认端点
	if config.AuthorizeEndpoint == "" {
		config.AuthorizeEndpoint = "/authorize"
	}
	if config.TokenEndpoint == "" {
		config.TokenEndpoint = "/token"
	}
	if config.MetadataEndpoint == "" {
		config.MetadataEndpoint = "/.well-known/oauth-authorization-server"
	}
	if config.JWKSEndpoint == "" {
		config.JWKSEndpoint = "/jwks"
	}
	if config.RegistrationEndpoint == "" {
		config.RegistrationEndpoint = "/register"
	}

	// 创建组件
	clientStore := NewSimpleInMemoryClientStore()
	keyManager := NewKeyManager(config.RSAPrivateKey)

	// // 创建 tokenManager（若使用 RSA，请确保在 config.RSAPrivateKey 非 nil 时设置）
	tokenManager := NewTokenManager(config.Issuer, nil)

	// 设置 RSA 密钥（如果提供）
	if config.RSAPrivateKey != nil {
		tokenManager.SetRSAKeys(config.RSAPrivateKey)
	}

	// 设置令牌生存时间
	tokenManager.AccessTokenTTL = config.AccessTokenTTL
	tokenManager.RefreshTokenTTL = config.RefreshTokenTTL

	// 创建 PKCE 管理器
	pkceConfig := &pkce.Config{
		ChallengeExpiry: 5 * time.Minute,
		MaxChallenges:   10000,
		VerifierLength:  128,
		EnableStats:     true,
		CleanupInterval: time.Minute,
	}

	pkceManager := pkce.NewManager(pkceConfig)

	authProv := NewDefaultAuthProvider(&AuthConfig{
		ServerURL:       config.Issuer,
		CodeTTL:         config.AuthCodeTTL,
		AccessTokenTTL:  config.AccessTokenTTL,
		RefreshTokenTTL: config.RefreshTokenTTL,
		SigningKey:      nil, // tokenManager 已管理签名
		PKCEConfig:      pkceConfig,
	})

	// 将 tokenManager 与 pkceManager 注入到 authProv（覆盖 NewDefaultAuthProvider 内部 map）
	authProv.TokenManager = tokenManager
	authProv.PkceManager = pkceManager

	server := &OAuthServerProvider{
		config:             config,
		clientStore:        clientStore,
		tokenManager:       tokenManager,
		keyManager:         keyManager,
		scopeManager:       NewScopeManager(),
		pkceManager:        pkceManager,
		mux:                http.NewServeMux(),
		authProvider:       authProv,
		registrationTokens: make(map[string]string),
	}
	// 注册路由
	server.setupRoutes()
	return server, nil
}

// setupRoutes 设置 HTTP 路由
func (s *OAuthServerProvider) setupRoutes() {
	s.mux.HandleFunc(s.config.AuthorizeEndpoint, s.handleAuthorize)
	s.mux.HandleFunc(s.config.TokenEndpoint, s.handleToken)
	s.mux.HandleFunc(s.config.MetadataEndpoint, s.handleMetadata)
	s.mux.HandleFunc(s.config.JWKSEndpoint, s.handleJWKS)
	s.mux.HandleFunc(s.config.RegistrationEndpoint, s.handleRegistration)

	if s.config.RevocationEndpoint != "" {
		s.mux.HandleFunc(s.config.RevocationEndpoint, s.handleRevocation)
	}
	if s.config.IntrospectionEndpoint != "" {
		s.mux.HandleFunc(s.config.IntrospectionEndpoint, s.handleIntrospection)
	}
}

// ServeHTTP 实现 http.Handler 接口
func (s *OAuthServerProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 设置安全头
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")

	s.mux.ServeHTTP(w, r)
}

// handleAuthorize 处理授权端点 /authorize
func (s *OAuthServerProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// OAuth 2.1 只支持 GET 和 POST
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	// 解析授权请求 - 现在返回 *AuthError
	authReq, authErr := s.parseAuthorizationRequest(r)
	if authErr != nil {
		s.writeErrorResponse(w, authErr, authReq.State)
		return
	}

	// 验证客户端
	client, err := s.clientStore.GetByID(ctx, authReq.ClientID)
	if err != nil {
		s.writeErrorResponse(w, errors.ErrInvalidClient, authReq.State)
		return
	}

	// 验证重定向 URI
	if !s.validateRedirectURI(authReq.RedirectURI, client.RedirectURIs) {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, authReq.State)
		return
	}

	// OAuth 2.1 强制要求 PKCE
	if authReq.CodeChallenge == "" || authReq.CodeChallengeMethod != "S256" {
		s.writeRedirectError(w, authReq.RedirectURI, "invalid_request",
			"OAuth 2.1 requires PKCE with S256 method", authReq.State)
		return
	}

	// 验证响应类型
	if !s.isValidResponseType(authReq.ResponseType, client.ResponseTypes) {
		s.writeRedirectError(w, authReq.RedirectURI, "unsupported_response_type",
			"Response type not supported", authReq.State)
		return
	}

	// 验证作用域
	validScopes, err := s.scopeManager.ValidateScopes(authReq.Scopes)
	if err != nil {
		// 转换 error 为 AuthError
		var authErr *errors.AuthError
		if ae, ok := err.(*errors.AuthError); ok {
			authErr = ae
		} else {
			authErr = &errors.AuthError{
				Code:        "invalid_scope",
				Description: err.Error(),
				HTTPStatus:  400,
			}
		}
		s.writeRedirectError(w, authReq.RedirectURI, authErr.Code,
			authErr.Description, authReq.State)
		return
	}

	// 用户身份验证
	user, err := s.config.UserAuthenticator.AuthenticateUser(ctx, r)
	if err != nil {
		// 重定向到登录页面
		s.redirectToLogin(w, r, authReq)
		return
	}

	// 用户授权检查
	authorized, err := s.config.UserAuthorizer.AuthorizeUser(ctx, user.UserID, authReq.ClientID, validScopes)
	if err != nil {
		s.writeRedirectError(w, authReq.RedirectURI, "server_error",
			"Authorization check failed", authReq.State)
		return
	}

	if !authorized {
		// 显示授权确认页面
		s.showConsentPage(w, r, authReq, client, validScopes)
		return
	}

	// 生成授权码
	authCode, err := s.generateAuthorizationCode(ctx, &AuthCodeRequest{
		ClientID:        authReq.ClientID,
		UserID:          user.UserID,
		Scopes:          validScopes,
		RedirectURI:     authReq.RedirectURI,
		CodeChallenge:   authReq.CodeChallenge,
		ChallengeMethod: authReq.CodeChallengeMethod,
		State:           authReq.State,
		ExpiresAt:       time.Now().Add(s.config.AuthCodeTTL),
	})
	if err != nil {
		s.writeRedirectError(w, authReq.RedirectURI, "server_error",
			"Failed to generate authorization code", authReq.State)
		return
	}

	// 重定向回客户端
	redirectURL := s.buildRedirectURL(authReq.RedirectURI, authCode, authReq.State)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleToken 处理令牌端点 /token
func (s *OAuthServerProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	// 只支持 POST
	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	// 解析令牌请求
	if err := r.ParseForm(); err != nil {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	grantType := r.Form.Get("grant_type")

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r)
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r)
	default:
		s.writeErrorResponse(w, errors.ErrUnsupportedGrantType, "")
	}
}

// parseClientCredentials 支持 Authorization: Basic 和表单形式
func (s *OAuthServerProvider) parseClientCredentials(r *http.Request) (clientID, clientSecret string) {
	// Authorization: Basic base64(client_id:client_secret)
	auth := r.Header.Get("Authorization")
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Basic") {
			if decoded, err := base64.StdEncoding.DecodeString(parts[1]); err == nil {
				cs := string(decoded)
				if idx := strings.IndexByte(cs, ':'); idx >= 0 {
					return cs[:idx], cs[idx+1:]
				}
			}
		}
	}

	// fallback 到表单
	_ = r.ParseForm()
	return r.Form.Get("client_id"), r.Form.Get("client_secret")
}

// handleAuthorizationCodeGrant 处理授权码授权
func (s *OAuthServerProvider) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// 解析客户端认证（支持 Basic 和 POST 两种）
	clientID, clientSecret := s.parseClientCredentials(r)

	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	codeVerifier := r.FormValue("code_verifier")

	if code == "" || clientID == "" || redirectURI == "" || codeVerifier == "" {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	tokenReq := &TokenRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
	}

	tokenResp, err := s.authProvider.ExchangeToken(ctx, code, tokenReq)
	if err != nil {
		if authErr, ok := err.(*errors.AuthError); ok {
			s.writeErrorResponse(w, authErr, "")
		} else {
			s.writeErrorResponse(w, errors.ErrServerError, "")
		}
		return
	}

	s.writeJSON(w, tokenResp)
}

// handleClientCredentialsGrant 处理客户端凭证授权
func (s *OAuthServerProvider) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	scopesStr := r.Form.Get("scope")

	// 使用统一的客户端认证解析
	clientID, clientSecret := s.parseClientCredentials(r)

	if clientID == "" {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	// 验证客户端凭证 - 这里应该始终验证密钥
	client, err := s.clientStore.GetByCredentials(ctx, clientID, clientSecret)
	if err != nil {
		s.writeErrorResponse(w, errors.ErrInvalidClient, "")
		return
	}

	// 对于客户端凭证流程，必须是机密客户端
	if client.ClientSecret == "" {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_client",
			Description: "Client credentials grant requires confidential client",
			HTTPStatus:  401,
		}, "")
		return
	}

	// 检查客户端是否支持客户端凭证授权
	if !s.containsString(client.GrantTypes, "client_credentials") {
		s.writeErrorResponse(w, errors.ErrUnsupportedGrantType, "")
		return
	}

	// 解析和验证作用域
	var scopes []string
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, " ")
	}

	validScopes, err := s.scopeManager.ValidateScopes(scopes)
	if err != nil {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_scope",
			Description: err.Error(),
			HTTPStatus:  400,
		}, "")
		return
	}

	// 生成访问令牌（客户端凭证模式没有用户ID）
	tokenResp, err := s.tokenManager.GenerateAccessToken("", clientID, validScopes)
	if err != nil {
		s.writeErrorResponse(w, errors.ErrServerError, "")
		return
	}

	// 客户端凭证模式不返回刷新令牌
	tokenResp.RefreshToken = ""

	s.writeTokenResponse(w, tokenResp)
}

// handleRefreshTokenGrant 处理刷新令牌授权
func (s *OAuthServerProvider) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	refreshToken := r.Form.Get("refresh_token")
	clientID := r.Form.Get("client_id")
	clientSecret := r.Form.Get("client_secret")

	if refreshToken == "" || clientID == "" {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	// 验证客户端凭证
	_, err := s.clientStore.GetByCredentials(ctx, clientID, clientSecret)
	if err != nil {
		s.writeErrorResponse(w, errors.ErrInvalidClient, "")
		return
	}

	// 使用 AuthProvider 刷新令牌
	authProvider := &DefaultAuthProvider{
		Config:       &AuthConfig{ServerURL: s.config.Issuer},
		TokenManager: s.tokenManager,
	}

	tokenResp, err := authProvider.RefreshToken(ctx, refreshToken)
	if err != nil {
		if authErr, ok := err.(*errors.AuthError); ok {
			s.writeErrorResponse(w, authErr, "")
		} else {
			s.writeErrorResponse(w, errors.ErrServerError, "")
		}
		return
	}

	s.writeTokenResponse(w, tokenResp)
}

// handleMetadata 处理元数据发现端点 /.well-known/oauth-authorization-server
func (s *OAuthServerProvider) handleMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	metadata := &ServerMetadata{
		Issuer:                s.config.Issuer,
		AuthorizationEndpoint: s.config.BaseURL + s.config.AuthorizeEndpoint,
		TokenEndpoint:         s.config.BaseURL + s.config.TokenEndpoint,
		JWKSUri:               s.config.BaseURL + s.config.JWKSEndpoint,
		RegistrationEndpoint:  s.config.BaseURL + s.config.RegistrationEndpoint,

		ResponseTypesSupported:            s.config.AllowedResponseTypes,
		GrantTypesSupported:               s.config.AllowedGrantTypes,
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic", "none"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ScopesSupported:                   s.config.AllowedScopes,
	}

	if s.config.RevocationEndpoint != "" {
		metadata.RevocationEndpoint = s.config.BaseURL + s.config.RevocationEndpoint
	}
	if s.config.IntrospectionEndpoint != "" {
		metadata.IntrospectionEndpoint = s.config.BaseURL + s.config.IntrospectionEndpoint
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// handleJWKS 处理 JWKS 端点 /jwks
func (s *OAuthServerProvider) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	jwks := s.keyManager.GetJWKS()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// handleRegistration 处理动态客户端注册端点 /register (RFC 7591)
func (s *OAuthServerProvider) handleRegistration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleClientRegistration(w, r)
	case http.MethodGet:
		s.handleClientInformation(w, r)
	case http.MethodPut:
		s.handleClientUpdate(w, r)
	case http.MethodDelete:
		s.handleClientDeletion(w, r)
	default:
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
	}
}

// handleClientRegistration 处理客户端注册
func (s *OAuthServerProvider) handleClientRegistration(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var regReq store.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&regReq); err != nil {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	// 验证注册请求
	if err := s.validateRegistrationRequest(&regReq); err != nil {
		s.writeErrorResponse(w, err, "")
		return
	}

	// 生成客户端凭证
	clientID := uuid.New().String()
	var clientSecret string
	if regReq.TokenEndpointAuthMethod != "none" {
		clientSecret = s.generateClientSecret()
	}

	// 创建客户端
	client := &store.OAuthClient{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientName:              regReq.ClientName,
		RedirectURIs:            regReq.RedirectURIs,
		GrantTypes:              regReq.GrantTypes,
		ResponseTypes:           regReq.ResponseTypes,
		Scope:                   regReq.Scope,
		TokenEndpointAuthMethod: regReq.TokenEndpointAuthMethod,
		CreatedAt:               time.Now(),
		LogoURI:                 regReq.LogoURI,
		ClientURI:               regReq.ClientURI,
		PolicyURI:               regReq.PolicyURI,
		TosURI:                  regReq.TosURI,
		Contacts:                regReq.Contacts,
	}

	// 生成注册访问令牌
	registrationAccessToken := s.generateRegistrationAccessToken()
	registrationClientURI := fmt.Sprintf("%s%s?client_id=%s",
		s.config.BaseURL, s.config.RegistrationEndpoint, clientID)

	// 存储客户端
	if err := s.clientStore.Create(ctx, client); err != nil {
		s.writeErrorResponse(w, errors.ErrServerError, "")
		return
	}

	// 记录 registrationAccessToken 到 server 映射（后续管理需要校验）
	s.mu.Lock()
	s.registrationTokens[registrationAccessToken] = clientID
	s.mu.Unlock()

	expiresAt := int64(0)
	// 返回注册响应
	regResp := store.ClientRegistrationResponse{
		ClientID:                client.ClientID,
		ClientSecret:            client.ClientSecret,
		ClientName:              client.ClientName,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		Scope:                   client.Scope,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		RegistrationAccessToken: registrationAccessToken,
		RegistrationClientURI:   registrationClientURI,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   &expiresAt, // 不过期
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(regResp)
}

// handleRevocation 处理令牌撤销端点
func (s *OAuthServerProvider) handleRevocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	// 撤销令牌
	err := s.tokenManager.RevokeToken(token)
	if err != nil {
		s.writeErrorResponse(w, errors.ErrServerError, "")
		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleIntrospection 处理令牌内省端点
func (s *OAuthServerProvider) handleIntrospection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	if err := r.ParseForm(); err != nil {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		s.writeErrorResponse(w, errors.ErrInvalidRequest, "")
		return
	}

	// 验证令牌
	tokenInfo, err := s.tokenManager.ValidateAccessToken(token)
	if err != nil {
		// 返回不活跃的令牌响应
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"active": false})
		return
	}

	// 返回令牌内省响应
	introspectionResp := map[string]interface{}{
		"active":     tokenInfo.Active,
		"sub":        tokenInfo.Subject,
		"client_id":  tokenInfo.ClientID,
		"scope":      strings.Join(tokenInfo.Scopes, " "),
		"exp":        tokenInfo.ExpiresAt.Unix(),
		"iat":        tokenInfo.IssuedAt.Unix(),
		"token_type": tokenInfo.TokenType,
	}

	if tokenInfo.Audience != nil {
		introspectionResp["aud"] = tokenInfo.Audience
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(introspectionResp)
}

// 辅助方法

// parseAuthorizationRequest 解析授权请求
func (s *OAuthServerProvider) parseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, *errors.AuthError) {
	query := r.URL.Query()

	req := &AuthorizationRequest{
		ClientID:            query.Get("client_id"),
		RedirectURI:         query.Get("redirect_uri"),
		State:               query.Get("state"),
		ResponseType:        query.Get("response_type"),
		CodeChallenge:       query.Get("code_challenge"),
		CodeChallengeMethod: query.Get("code_challenge_method"),
	}

	// 解析作用域
	if scopeStr := query.Get("scope"); scopeStr != "" {
		req.Scopes = strings.Split(scopeStr, " ")
	}

	// 基本验证
	if req.ClientID == "" || req.RedirectURI == "" || req.ResponseType == "" {
		return req, errors.ErrInvalidRequest
	}

	return req, nil
}

// validateRedirectURI 验证重定向 URI
func (s *OAuthServerProvider) validateRedirectURI(redirectURI string, registeredURIs []string) bool {
	for _, registered := range registeredURIs {
		if redirectURI == registered {
			return true
		}
	}
	return false
}

// isValidResponseType 验证响应类型
func (s *OAuthServerProvider) isValidResponseType(responseType string, clientResponseTypes []string) bool {
	// 检查服务器是否支持
	if !s.containsString(s.config.AllowedResponseTypes, responseType) {
		return false
	}

	// 检查客户端是否支持
	return s.containsString(clientResponseTypes, responseType)
}

// containsString 检查字符串数组是否包含指定字符串
func (s *OAuthServerProvider) containsString(arr []string, str string) bool {
	for _, item := range arr {
		if item == str {
			return true
		}
	}
	return false
}

// generateAuthorizationCode delegates to DefaultAuthProvider.GenerateAuthorizationCode for consistency
func (s *OAuthServerProvider) generateAuthorizationCode(ctx context.Context, req *AuthCodeRequest) (string, error) {
	// Use DefaultAuthProvider's generator so storage/format is consistent
	authProvider := &DefaultAuthProvider{
		Config:       &AuthConfig{ServerURL: s.config.Issuer},
		TokenManager: s.tokenManager,
		AuthCodes:    make(map[string]*AuthorizationCode),
		PkceManager:  s.pkceManager,
	}

	return authProvider.GenerateAuthorizationCode(ctx, req)
}

// buildRedirectURL 构建重定向 URL
func (s *OAuthServerProvider) buildRedirectURL(baseURL, code, state string) string {
	u, _ := url.Parse(baseURL)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// generateClientSecret 生成客户端密钥
func (s *OAuthServerProvider) generateClientSecret() string {
	return uuid.New().String()
}

// generateRegistrationAccessToken 生成注册访问令牌
func (s *OAuthServerProvider) generateRegistrationAccessToken() string {
	return uuid.New().String()
}

// writeErrorResponse 写入错误响应
func (s *OAuthServerProvider) writeErrorResponse(w http.ResponseWriter, err *errors.AuthError, state string) {
	w.Header().Set("Content-Type", "application/json")

	if err.HTTPStatus != 0 {
		w.WriteHeader(err.HTTPStatus)
	} else {
		w.WriteHeader(http.StatusBadRequest)
	}

	errorResp := map[string]interface{}{
		"error":             err.Code,
		"error_description": err.Description,
	}

	if state != "" {
		errorResp["state"] = state
	}

	json.NewEncoder(w).Encode(errorResp)
}

// writeRedirectError 写入重定向错误
func (s *OAuthServerProvider) writeRedirectError(w http.ResponseWriter, redirectURI, errorCode, errorDesc, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDesc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, &http.Request{}, u.String(), http.StatusFound)
}

// writeTokenResponse 写入令牌响应
func (s *OAuthServerProvider) writeTokenResponse(w http.ResponseWriter, tokenResp *TokenResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	json.NewEncoder(w).Encode(tokenResp)
}

// redirectToLogin 重定向到登录页面
func (s *OAuthServerProvider) redirectToLogin(w http.ResponseWriter, r *http.Request, authReq *AuthorizationRequest) {
	// 实现登录页面重定向逻辑
	loginURL := "/login?redirect_uri=" + url.QueryEscape(r.URL.String())
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// showConsentPage 显示授权确认页面
func (s *OAuthServerProvider) showConsentPage(w http.ResponseWriter, r *http.Request, authReq *AuthorizationRequest, client *store.OAuthClient, scopes []string) {
	// 实现授权确认页面显示逻辑
	// 这里应该渲染一个 HTML 页面让用户确认授权
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(`
		<html>
		<body>
			<h2>Authorization Required</h2>
			<p>Application "` + client.ClientName + `" is requesting access to your account.</p>
			<p>Requested scopes: ` + strings.Join(scopes, ", ") + `</p>
			<form method="post">
				<input type="hidden" name="client_id" value="` + authReq.ClientID + `">
				<input type="hidden" name="state" value="` + authReq.State + `">
				<input type="submit" name="authorize" value="Allow">
				<input type="submit" name="deny" value="Deny">
			</form>
		</body>
		</html>
	`))
}

// validateRegistrationRequest 验证注册请求
func (s *OAuthServerProvider) validateRegistrationRequest(req *store.ClientRegistrationRequest) *errors.AuthError {
	if len(req.RedirectURIs) == 0 {
		return &errors.AuthError{
			Code:        "invalid_redirect_uri",
			Description: "redirect_uris is required",
			HTTPStatus:  400,
		}
	}

	// 验证重定向 URI 格式
	for _, uri := range req.RedirectURIs {
		if _, err := url.Parse(uri); err != nil {
			return &errors.AuthError{
				Code:        "invalid_redirect_uri",
				Description: "Invalid redirect URI format",
				HTTPStatus:  400,
			}
		}
	}

	// 设置默认值
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	return nil
}

// handleClientInformation 处理客户端信息查询
func (s *OAuthServerProvider) handleClientInformation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_request",
			Description: "client_id parameter is required",
			HTTPStatus:  400,
		}, "")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !s.validateRegistrationAccessToken(authHeader, clientID) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_token",
			Description: "Invalid or missing registration access token",
			HTTPStatus:  401,
		}, "")
		return
	}

	client, err := s.clientStore.GetByID(ctx, clientID)
	if err != nil {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_client_id",
			Description: "Client not found",
			HTTPStatus:  404,
		}, "")
		return
	}

	// 确保有绑定的 token（不存在则生成并存储）
	var regToken string
	s.mu.RLock()
	for t, cid := range s.registrationTokens {
		if cid == clientID {
			regToken = t
			break
		}
	}
	s.mu.RUnlock()
	if regToken == "" {
		regToken = s.generateRegistrationAccessToken()
		s.storeRegistrationToken(regToken, clientID)
	}

	expiresAt := int64(0)
	clientInfo := store.ClientRegistrationResponse{
		ClientID:                client.ClientID,
		ClientSecret:            client.ClientSecret,
		ClientName:              client.ClientName,
		RedirectURIs:            client.RedirectURIs,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		Scope:                   client.Scope,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		LogoURI:                 client.LogoURI,
		ClientURI:               client.ClientURI,
		PolicyURI:               client.PolicyURI,
		TosURI:                  client.TosURI,
		Contacts:                client.Contacts,
		ClientIDIssuedAt:        client.CreatedAt.Unix(),
		ClientSecretExpiresAt:   &expiresAt,
		RegistrationAccessToken: regToken,
		RegistrationClientURI: fmt.Sprintf("%s%s?client_id=%s",
			s.config.BaseURL, s.config.RegistrationEndpoint, clientID),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clientInfo)
}
func (s *OAuthServerProvider) handleClientUpdate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_request",
			Description: "client_id parameter is required",
			HTTPStatus:  400,
		}, "")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !s.validateRegistrationAccessToken(authHeader, clientID) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_token",
			Description: "Invalid or missing registration access token",
			HTTPStatus:  401,
		}, "")
		return
	}

	existingClient, err := s.clientStore.GetByID(ctx, clientID)
	if err != nil {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_client_id",
			Description: "Client not found",
			HTTPStatus:  404,
		}, "")
		return
	}

	var updateReq store.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&updateReq); err != nil {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_request",
			Description: "Invalid JSON in request body",
			HTTPStatus:  400,
		}, "")
		return
	}

	if err := s.validateRegistrationRequest(&updateReq); err != nil {
		s.writeErrorResponse(w, err, "")
		return
	}

	// 更新客户端信息（client_id 与 secret 不变）
	updatedClient := &store.OAuthClient{
		ClientID:                existingClient.ClientID,
		ClientSecret:            existingClient.ClientSecret,
		ClientName:              updateReq.ClientName,
		RedirectURIs:            updateReq.RedirectURIs,
		GrantTypes:              updateReq.GrantTypes,
		ResponseTypes:           updateReq.ResponseTypes,
		Scope:                   updateReq.Scope,
		TokenEndpointAuthMethod: updateReq.TokenEndpointAuthMethod,
		LogoURI:                 updateReq.LogoURI,
		ClientURI:               updateReq.ClientURI,
		PolicyURI:               updateReq.PolicyURI,
		TosURI:                  updateReq.TosURI,
		Contacts:                updateReq.Contacts,
		CreatedAt:               existingClient.CreatedAt,
		UpdatedAt:               time.Now(),
	}

	if err := s.clientStore.Update(ctx, updatedClient); err != nil {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "server_error",
			Description: "Failed to update client",
			HTTPStatus:  500,
		}, "")
		return
	}

	// 生成新的注册 token（旧的作废）
	newRegToken := s.generateRegistrationAccessToken()
	s.removeRegistrationTokensForClient(clientID)
	s.storeRegistrationToken(newRegToken, clientID)

	expiresAt := int64(0)
	updateResp := store.ClientRegistrationResponse{
		ClientID:                updatedClient.ClientID,
		ClientSecret:            updatedClient.ClientSecret,
		ClientName:              updatedClient.ClientName,
		RedirectURIs:            updatedClient.RedirectURIs,
		GrantTypes:              updatedClient.GrantTypes,
		ResponseTypes:           updatedClient.ResponseTypes,
		Scope:                   updatedClient.Scope,
		TokenEndpointAuthMethod: updatedClient.TokenEndpointAuthMethod,
		LogoURI:                 updatedClient.LogoURI,
		ClientURI:               updatedClient.ClientURI,
		PolicyURI:               updatedClient.PolicyURI,
		TosURI:                  updatedClient.TosURI,
		Contacts:                updatedClient.Contacts,
		RegistrationAccessToken: newRegToken,
		RegistrationClientURI: fmt.Sprintf("%s%s?client_id=%s",
			s.config.BaseURL, s.config.RegistrationEndpoint, clientID),
		ClientIDIssuedAt:      updatedClient.CreatedAt.Unix(),
		ClientSecretExpiresAt: &expiresAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updateResp)
}

func (s *OAuthServerProvider) handleClientDeletion(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_request",
			Description: "client_id parameter is required",
			HTTPStatus:  400,
		}, "")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !s.validateRegistrationAccessToken(authHeader, clientID) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_token",
			Description: "Invalid or missing registration access token",
			HTTPStatus:  401,
		}, "")
		return
	}

	if _, err := s.clientStore.GetByID(ctx, clientID); err != nil {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "invalid_client_id",
			Description: "Client not found",
			HTTPStatus:  404,
		}, "")
		return
	}

	if err := s.revokeAllClientTokens(ctx, clientID); err != nil {
		fmt.Printf("Warning: Failed to revoke tokens for client %s: %v\n", clientID, err)
	}

	if err := s.clientStore.Delete(ctx, clientID); err != nil {
		s.writeErrorResponse(w, &errors.AuthError{
			Code:        "server_error",
			Description: "Failed to delete client",
			HTTPStatus:  500,
		}, "")
		return
	}

	// 删除该 clientID 的所有注册 token
	s.removeRegistrationTokensForClient(clientID)

	w.WriteHeader(http.StatusNoContent)
}

// 从 Authorization header 提取 Bearer token
func (s *OAuthServerProvider) extractBearerToken(authHeader string) string {
	parts := strings.Fields(authHeader)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// 验证注册访问令牌是否有效且匹配 clientID
func (s *OAuthServerProvider) validateRegistrationAccessToken(authHeader, clientID string) bool {
	token := s.extractBearerToken(authHeader)
	if token == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	mappedClient, ok := s.registrationTokens[token]
	return ok && mappedClient == clientID
}

// 保存新的注册 token
func (s *OAuthServerProvider) storeRegistrationToken(token, clientID string) {
	s.mu.Lock()
	s.registrationTokens[token] = clientID
	s.mu.Unlock()
}

// 删除某 clientID 的所有注册 token
func (s *OAuthServerProvider) removeRegistrationTokensForClient(clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, cid := range s.registrationTokens {
		if cid == clientID {
			delete(s.registrationTokens, token)
		}
	}
}

// revokeAllClientTokens 撤销指定客户端的所有访问令牌和刷新令牌
func (s *OAuthServerProvider) revokeAllClientTokens(ctx context.Context, clientID string) error {
	if s.tokenManager == nil {
		return fmt.Errorf("token manager not initialized")
	}
	return s.tokenManager.RevokeAllTokensForClient(clientID)
}

func (s *OAuthServerProvider) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
