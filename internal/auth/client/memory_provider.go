package client

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

type InMemoryOAuthClientProvider struct {
	redirectURL    string
	clientMetadata auth.OAuthClientMetadata
	clientInfo     *auth.OAuthClientInformation
	tokens         *auth.OAuthTokens
	codeVerifier   string
	onRedirect     func(*url.URL) error
	mutex          sync.RWMutex
}

func NewInMemoryOAuthClientProvider(
	redirectURL string,
	clientMetadata auth.OAuthClientMetadata,
	onRedirect func(*url.URL) error) *InMemoryOAuthClientProvider {
	if onRedirect == nil {
		onRedirect = func(u *url.URL) error {
			return nil
		}
	}
	return &InMemoryOAuthClientProvider{
		redirectURL:    redirectURL,
		clientMetadata: clientMetadata,
		onRedirect:     onRedirect,
	}
}
func (p *InMemoryOAuthClientProvider) RedirectURL() string {
	return p.redirectURL
}
func (p *InMemoryOAuthClientProvider) ClientMetadata() auth.OAuthClientMetadata {
	return p.clientMetadata
}

func (p *InMemoryOAuthClientProvider) ClientInformation() *auth.OAuthClientInformation {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.clientInfo
}
func (p *InMemoryOAuthClientProvider) SaveClientInformation(clientInformation auth.OAuthClientInformationFull) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.clientInfo = &auth.OAuthClientInformation{
		ClientID:              clientInformation.ClientID,
		ClientSecret:          clientInformation.ClientSecret,
		ClientIDIssuedAt:      clientInformation.ClientIDIssuedAt,
		ClientSecretExpiresAt: clientInformation.ClientSecretExpiresAt,
	}
}
func (p *InMemoryOAuthClientProvider) Tokens() *auth.OAuthTokens {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.tokens
}
func (p *InMemoryOAuthClientProvider) SaveTokens(tokens auth.OAuthTokens) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.tokens = &tokens
}
func (p *InMemoryOAuthClientProvider) RedirectToAuthorization(authorizationUrl *url.URL) error {
	return p.onRedirect(authorizationUrl)
}
func (p *InMemoryOAuthClientProvider) CodeVerifier() (string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.codeVerifier == "" {
		return "", fmt.Errorf("no code verifier saved")
	}
	return p.codeVerifier, nil
}

func (p *InMemoryOAuthClientProvider) SaveCodeVerifier(codeVerifier string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.codeVerifier = codeVerifier
}

// 可选方法的默认实现
func (p *InMemoryOAuthClientProvider) State() (string, error) {
	// 返回空字符串表示不使用 state
	return "", nil
}

func (p *InMemoryOAuthClientProvider) AddClientAuthentication(headers http.Header, params url.Values, tokenUrl string) error {
	// 默认不添加自定义认证
	return nil
}

func (p *InMemoryOAuthClientProvider) ValidateResourceURL(serverUrl, resource string) (*url.URL, error) {
	// 默认不进行额外验证
	return nil, nil
}

func (p *InMemoryOAuthClientProvider) InvalidateCredentials(scope string) error {
	// 根据 scope 清除相应凭据
	switch scope {
	case "all":
		p.clientInfo = nil
		p.tokens = nil
		p.codeVerifier = ""
	case "client":
		p.clientInfo = nil
	case "tokens":
		p.tokens = nil
	case "verifier":
		p.codeVerifier = ""
	}
	return nil
}
