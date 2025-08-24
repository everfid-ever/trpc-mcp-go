package client

import (
	"net/http"
	"net/url"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

// OAuthClientProvider defines core OAuth 2.0 client operations.
// Handles client config, tokens, and authorization flow.
type OAuthClientProvider interface {
	RedirectURL() string
	ClientMetadata() auth.OAuthClientMetadata
	ClientInformation() *auth.OAuthClientInformation
	Tokens() (*auth.OAuthTokens, error)
	SaveTokens(tokens auth.OAuthTokens) error
	RedirectToAuthorization(authorizationUrl *url.URL) error
	SaveCodeVerifier(codeVerifier string) error
	CodeVerifier() (string, error)
}

// OAuthStateProvider adds state parameter management for CSRF protection.
type OAuthStateProvider interface {
	State() (string, error)
}

// OAuthClientInfoProvider handles dynamic client credential storage.
type OAuthClientInfoProvider interface {
	SaveClientInformation(clientInformation auth.OAuthClientInformationFull) error
}

// OAuthClientAuthProvider enables custom client authentication methods.
type OAuthClientAuthProvider interface {
	AddClientAuthentication(headers http.Header, params url.Values, tokenUrl string) error
}

// OAuthResourceValidator validates resource URLs for specific server requirements.
type OAuthResourceValidator interface {
	ValidateResourceURL(serverUrl *url.URL, resourceMetadata *auth.OAuthProtectedResourceMetadata) (*url.URL, error)
}

// OAuthCredentialInvalidator handles logout and credential revocation.
type OAuthCredentialInvalidator interface {
	InvalidateCredentials(scope string) error
}
