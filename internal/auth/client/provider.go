package client

import (
	"net/http"
	"net/url"

	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
)

type OAuthClientProvider interface {
	RedirectURL() string
	ClientMetadata() auth.OAuthClientMetadata
	State() (string, error)
	ClientInformation() *auth.OAuthClientInformation
	SaveClientInformation(clientInformation auth.OAuthClientInformationFull)
	Tokens() *auth.OAuthTokens
	SaveTokens(tokens auth.OAuthTokens)
	RedirectToAuthorization(authorizationUrl *url.URL) error
	SaveCodeVerifier(codeVerifier string)
	CodeVerifier() (string, error)
	AddClientAuthentication(headers http.Header, params url.Values, tokenUrl string) error
	ValidateResourceURL(serverUrl, resource string) (*url.URL, error)
	InvalidateCredentials(scope string) error
}
