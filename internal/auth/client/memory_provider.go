package client

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
func (p *InMemoryOAuthClientProvider) SaveClientInformation(clientInformation auth.OAuthClientInformationFull) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.clientInfo = &auth.OAuthClientInformation{
		ClientID:              clientInformation.ClientID,
		ClientSecret:          clientInformation.ClientSecret,
		ClientIDIssuedAt:      clientInformation.ClientIDIssuedAt,
		ClientSecretExpiresAt: clientInformation.ClientSecretExpiresAt,
	}
	return nil
}
func (p *InMemoryOAuthClientProvider) Tokens() (*auth.OAuthTokens, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	return p.tokens, nil
}
func (p *InMemoryOAuthClientProvider) SaveTokens(tokens auth.OAuthTokens) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.tokens = &tokens
	return nil
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

func (p *InMemoryOAuthClientProvider) SaveCodeVerifier(codeVerifier string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.codeVerifier = codeVerifier
	return nil
}

// 可选方法的默认实现
func (p *InMemoryOAuthClientProvider) State() (string, error) {
	// Generate a random state parameter for CSRF protection
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random state: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func (p *InMemoryOAuthClientProvider) AddClientAuthentication(headers http.Header, params url.Values, tokenUrl string) error {
	// Add client authentication using client_secret_post method
	p.mutex.RLock()
	clientInfo := p.clientInfo
	p.mutex.RUnlock()
	
	if clientInfo != nil && clientInfo.ClientID != "" {
		params.Set("client_id", clientInfo.ClientID)
		if clientInfo.ClientSecret != "" {
			params.Set("client_secret", clientInfo.ClientSecret)
		}
	}
	return nil
}

func (p *InMemoryOAuthClientProvider) ValidateResourceURL(serverUrl *url.URL, resourceMetadata *auth.OAuthProtectedResourceMetadata) (*url.URL, error) {
	// If no resource metadata provided, return nil (no resource parameter needed)
	if resourceMetadata == nil {
		return nil, nil
	}
	
	// Parse the resource URL from metadata
	resourceURL, err := url.Parse(resourceMetadata.Resource)
	if err != nil {
		return nil, fmt.Errorf("invalid resource URL in metadata: %w", err)
	}
	
	// Basic validation: ensure the resource URL has the same origin as server URL
	if resourceURL.Scheme != serverUrl.Scheme || resourceURL.Host != serverUrl.Host {
		// Allow if resource URL is a more specific path under the same origin
		if !strings.HasPrefix(resourceURL.String(), serverUrl.Scheme+"://"+serverUrl.Host) {
			return nil, fmt.Errorf("resource URL %s does not match server origin %s://%s", 
				resourceURL.String(), serverUrl.Scheme, serverUrl.Host)
		}
	}
	
	return resourceURL, nil
}

func (p *InMemoryOAuthClientProvider) InvalidateCredentials(scope string) error {
	// 根据 scope 清除相应凭据，使用互斥锁保护
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
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
	default:
		return fmt.Errorf("unknown invalidation scope: %s", scope)
	}
	return nil
}
