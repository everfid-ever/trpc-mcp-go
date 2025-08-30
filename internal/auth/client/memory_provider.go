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
	state          string
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

// OAuthStateProvider implementation
func (p *InMemoryOAuthClientProvider) State() (string, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.state == "" {
		return "", fmt.Errorf("no state parameter saved")
	}
	return p.state, nil
}

// Helper method to save state (not part of interface but useful)
func (p *InMemoryOAuthClientProvider) SaveState(state string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.state = state
	return nil
}

func (p *InMemoryOAuthClientProvider) AddClientAuthentication(headers http.Header, params url.Values, tokenUrl string) error {
	// Default implementation: no custom authentication
	// Subclasses can override this for custom auth methods
	return nil
}

func (p *InMemoryOAuthClientProvider) ValidateResourceURL(serverUrl *url.URL, resourceMetadata *auth.OAuthProtectedResourceMetadata) (*url.URL, error) {
	// Default implementation: return the server URL as-is
	// Subclasses can override this for custom validation logic
	return serverUrl, nil
}

func (p *InMemoryOAuthClientProvider) InvalidateCredentials(scope string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	// Clear credentials based on scope
	switch scope {
	case "all":
		p.clientInfo = nil
		p.tokens = nil
		p.codeVerifier = ""
		p.state = ""
	case "client":
		p.clientInfo = nil
	case "tokens":
		p.tokens = nil
	case "verifier":
		p.codeVerifier = ""
	case "state":
		p.state = ""
	default:
		return fmt.Errorf("unknown invalidation scope: %s", scope)
	}
	return nil
}
