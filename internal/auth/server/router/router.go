package router

import (
	"fmt"
	"net/http"
	"net/url"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/handler"
)

// AuthRouterOptions holds configuration options for the MCP authentication router.
type AuthRouterOptions struct {
	Provider                  server.OAuthServerProvider
	IssuerUrl                 *url.URL
	BaseUrl                   *url.URL
	ServiceDocumentationUrl   *url.URL
	ScopesSupported           []string
	ResourceName              *string
	AuthorizationOptions      *handler.AuthorizationHandlerOptions
	ClientRegistrationOptions *handler.ClientRegistrationHandlerOptions
	RevocationOptions         *handler.RevocationHandlerOptions
	TokenOptions              *handler.TokenHandlerOptions
}

// AuthMetadataOptions holds configuration options for the MCP authentication metadata endpoints.
type AuthMetadataOptions struct {
	OAuthMetadata           auth.OAuthMetadata
	ResourceServerUrl       *url.URL
	ServiceDocumentationUrl *url.URL
	ScopesSupported         []string
	ResourceName            *string
}

// checkIssuerUrl validates the issuer URL according to RFC 8414.
func checkIssuerUrl(issuer *url.URL) error {
	// Technically RFC 8414 does not permit a localhost HTTPS exemption,
	// but this will be necessary for ease of testing
	if issuer.Scheme != "https" && issuer.Hostname() != "localhost" && issuer.Hostname() != "127.0.0.1" {
		return fmt.Errorf("issuer URL must be HTTPS")
	}
	if issuer.Fragment != "" {
		return fmt.Errorf("issuer URL must not have a fragment: %s", issuer.String())
	}
	if issuer.RawQuery != "" {
		return fmt.Errorf("issuer URL must not have a query string: %s", issuer.String())
	}
	return nil
}

// supportsClientRegistration checks if the provider supports dynamic client registration
func supportsClientRegistration(provider server.OAuthServerProvider) bool {
	clientsStore := provider.ClientsStore()
	if clientsStore == nil {
		return false
	}
	// Use type assertion to check if the clients store implements SupportDynamicClientRegistration interface
	_, ok := provider.(server.SupportTokenRevocation)
	return ok
}

// supportsTokenRevocation checks if the provider supports token revocation
func supportsTokenRevocation(provider server.OAuthServerProvider) bool {
	// Use type assertion to check if the provider implements SupportTokenRevocation interface
	_, ok := provider.(server.SupportTokenRevocation)
	return ok
}

// CreateOAuthMetadata generates OAuth 2.1 compliant Authorization Server Metadata.
func CreateOAuthMetadata(options struct {
	Provider                server.OAuthServerProvider
	IssuerUrl               *url.URL
	BaseUrl                 *url.URL
	ServiceDocumentationUrl *url.URL
	ScopesSupported         []string
}) (auth.OAuthMetadata, error) {
	issuer := options.IssuerUrl
	baseUrl := options.BaseUrl

	// Validate issuer URL
	if err := checkIssuerUrl(issuer); err != nil {
		return auth.OAuthMetadata{}, err
	}

	// Determine base URL for endpoints
	var baseUrlForEndpoints *url.URL
	if baseUrl != nil {
		baseUrlForEndpoints = baseUrl
	} else {
		baseUrlForEndpoints = issuer
	}

	// Required endpoints
	authorizationEndpoint := "/authorize"
	tokenEndpoint := "/token"

	authEndpointUrl, _ := url.Parse(authorizationEndpoint)
	tokenEndpointUrl, _ := url.Parse(tokenEndpoint)

	metadata := auth.OAuthMetadata{
		// Core fields
		Issuer:                issuer.String(),
		AuthorizationEndpoint: baseUrlForEndpoints.ResolveReference(authEndpointUrl).String(),
		TokenEndpoint:         baseUrlForEndpoints.ResolveReference(tokenEndpointUrl).String(),

		// OAuth 2.1 requires PKCE support
		ResponseTypesSupported:        []string{"code"}, // OAuth 2.1 removes implicit flow
		CodeChallengeMethodsSupported: []string{"S256"}, // OAuth 2.1 requires S256, plain is deprecated

		// Token endpoint authentication methods
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post", "client_secret_basic"},

		// OAuth 2.1 supported grant types
		GrantTypesSupported: []string{"authorization_code", "refresh_token"},

		// Optional fields
		ScopesSupported: options.ScopesSupported,
	}

	// Add service documentation if provided
	if options.ServiceDocumentationUrl != nil {
		serviceDoc := options.ServiceDocumentationUrl.String()
		metadata.ServiceDocumentation = &serviceDoc
	}

	// Check for optional endpoints based on provider capabilities
	if supportsTokenRevocation(options.Provider) {
		revocationEndpoint := "/revoke"
		revEndpointUrl, _ := url.Parse(revocationEndpoint)
		revEndpoint := baseUrlForEndpoints.ResolveReference(revEndpointUrl).String()
		metadata.RevocationEndpoint = &revEndpoint
		metadata.RevocationEndpointAuthMethodsSupported = []string{"client_secret_post", "client_secret_basic"}
	}

	if supportsClientRegistration(options.Provider) {
		registrationEndpoint := "/register"
		regEndpointUrl, _ := url.Parse(registrationEndpoint)
		regEndpoint := baseUrlForEndpoints.ResolveReference(regEndpointUrl).String()
		metadata.RegistrationEndpoint = &regEndpoint
	}

	return metadata, nil
}

// McpAuthRouter sets up OAuth 2.1 compliant MCP authorization server endpoints
func McpAuthRouter(mux *http.ServeMux, options AuthRouterOptions) error {
	// Create OAuth metadata with error handling
	oauthMetadata, err := CreateOAuthMetadata(struct {
		Provider                server.OAuthServerProvider
		IssuerUrl               *url.URL
		BaseUrl                 *url.URL
		ServiceDocumentationUrl *url.URL
		ScopesSupported         []string
	}{
		Provider:                options.Provider,
		IssuerUrl:               options.IssuerUrl,
		BaseUrl:                 options.BaseUrl,
		ServiceDocumentationUrl: options.ServiceDocumentationUrl,
		ScopesSupported:         options.ScopesSupported,
	})
	if err != nil {
		return fmt.Errorf("failed to create OAuth metadata: %w", err)
	}

	// Authorization endpoint (GET only for OAuth 2.1)
	authorizationURL, _ := url.Parse(oauthMetadata.AuthorizationEndpoint)
	authzOptions := handler.AuthorizationHandlerOptions{
		Provider: options.Provider,
	}
	if options.AuthorizationOptions != nil && options.AuthorizationOptions.RateLimit != nil {
		authzOptions.RateLimit = options.AuthorizationOptions.RateLimit
	}
	mux.Handle("GET "+authorizationURL.Path, handler.AuthorizationHandler(authzOptions))

	// Token endpoint (POST only for OAuth 2.1)
	tokenURL, _ := url.Parse(oauthMetadata.TokenEndpoint)
	tokenOptions := handler.TokenHandlerOptions{
		Provider: options.Provider,
	}
	if options.TokenOptions != nil && options.TokenOptions.RateLimit != nil {
		tokenOptions.RateLimit = options.TokenOptions.RateLimit
	}
	mux.Handle("POST "+tokenURL.Path, handler.TokenHandler(tokenOptions))

	// Metadata endpoints
	issuerURL, _ := url.Parse(oauthMetadata.Issuer)
	if err := McpAuthMetadataRouter(mux, AuthMetadataOptions{
		OAuthMetadata:           oauthMetadata,
		ResourceServerUrl:       issuerURL,
		ServiceDocumentationUrl: options.ServiceDocumentationUrl,
		ScopesSupported:         options.ScopesSupported,
		ResourceName:            options.ResourceName,
	}); err != nil {
		return fmt.Errorf("failed to setup metadata router: %w", err)
	}

	// Dynamic client registration (optional, POST only)
	if oauthMetadata.RegistrationEndpoint != nil {
		registrationURL, _ := url.Parse(*oauthMetadata.RegistrationEndpoint)
		clientsStore := options.Provider.ClientsStore()

		regOpts := handler.ClientRegistrationHandlerOptions{
			ClientsStore: clientsStore,
		}

		if options.ClientRegistrationOptions != nil {
			regOpts = *options.ClientRegistrationOptions
			regOpts.ClientsStore = clientsStore
		} else {
			// OAuth 2.1 recommended rate limiting for client registration
			regOpts.RateLimit = &handler.RegisterRateLimitConfig{
				WindowMs: 60000, // 1 minute window
				Max:      10,    // Max 10 registrations per minute
			}
		}

		mux.Handle("POST "+registrationURL.Path, handler.ClientRegistrationHandler(regOpts))
	}

	// 5) Token revocation endpoint (optional, POST only)
	if oauthMetadata.RevocationEndpoint != nil {
		revocationURL, _ := url.Parse(*oauthMetadata.RevocationEndpoint)

		revOpts := handler.RevocationHandlerOptions{
			Provider: options.Provider,
		}
		if options.RevocationOptions != nil && options.RevocationOptions.RateLimit != nil {
			revOpts.RateLimit = options.RevocationOptions.RateLimit
		}

		mux.Handle("POST "+revocationURL.Path, handler.RevocationHandler(revOpts))
	}

	return nil
}

// McpAuthMetadataRouter sets up OAuth 2.1 compliant metadata endpoints
func McpAuthMetadataRouter(mux *http.ServeMux, options AuthMetadataOptions) error {
	issuerURL, _ := url.Parse(options.OAuthMetadata.Issuer)
	if err := checkIssuerUrl(issuerURL); err != nil {
		return fmt.Errorf("invalid issuer URL in metadata: %w", err)
	}

	// Create protected resource metadata
	protectedResourceMetadata := auth.OAuthProtectedResourceMetadata{
		Resource: options.ResourceServerUrl.String(),
		AuthorizationServers: []string{
			options.OAuthMetadata.Issuer,
		},
		ScopesSupported: options.ScopesSupported,
	}

	// Add optional fields
	if options.ResourceName != nil {
		protectedResourceMetadata.ResourceName = options.ResourceName
	}

	if options.ServiceDocumentationUrl != nil {
		resourceDoc := options.ServiceDocumentationUrl.String()
		protectedResourceMetadata.ResourceDocumentation = &resourceDoc
	}

	// Protected resource metadata endpoint (GET only)
	mux.Handle("GET /.well-known/oauth-protected-resource",
		handler.MetadataHandler(protectedResourceMetadata))

	// Authorization server metadata endpoint (GET only, for backward compatibility)
	mux.Handle("GET /.well-known/oauth-authorization-server",
		handler.MetadataHandler(options.OAuthMetadata))

	return nil
}

// GetOAuthProtectedResourceMetadataUrl constructs the OAuth 2.0 Protected Resource Metadata URL from a given server URL
func GetOAuthProtectedResourceMetadataUrl(serverUrl *url.URL) string {
	metadataUrl, _ := url.Parse("/.well-known/oauth-protected-resource")
	return serverUrl.ResolveReference(metadataUrl).String()
}

// InstallMCPAuthRoutes convenience function to simplify OAuth 2.1 compliant route installation
func InstallMCPAuthRoutes(
	mux *http.ServeMux,
	issuerBaseURL string,                // OAuth metadata issuer (e.g. https://auth.example.com)
	resourceServerURL string,            // Your MCP service URL (e.g. https://api.example.com/mcp)
	provider server.OAuthServerProvider, // Your server provider interface
	scopesSupported []string,            // Can be nil
	resourceName *string,                // Can be nil
	serviceDocURL *string,               // Can be nil
) error {
	issuerURL, err := url.Parse(issuerBaseURL)
	if err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}

	var serviceDocumentationUrl *url.URL
	if serviceDocURL != nil {
		serviceDocumentationUrl, err = url.Parse(*serviceDocURL)
		if err != nil {
			return fmt.Errorf("invalid service documentation URL: %w", err)
		}
	}

	options := AuthRouterOptions{
		Provider:                provider,
		IssuerUrl:               issuerURL,
		ServiceDocumentationUrl: serviceDocumentationUrl,
		ScopesSupported:         scopesSupported,
		ResourceName:            resourceName,
	}

	return McpAuthRouter(mux, options)
}
