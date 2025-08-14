package router

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"net/url"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/handler"
)

// AuthRouterOptions holds configuration options for the MCP authentication router.
type AuthRouterOptions struct {
	// Provider implementing the actual authorization logic for this router.
	Provider server.OAuthServerProvider

	// The authorization server's issuer identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
	IssuerUrl *url.URL

	// The base URL of the authorization server to use for the metadata endpoints.
	// If not provided, the issuer URL will be used as the base URL.
	BaseUrl *url.URL

	// An optional URL of a page containing human-readable information that developers might want or need to know when using the authorization server.
	ServiceDocumentationUrl *url.URL

	// An optional list of scopes supported by this authorization server
	ScopesSupported []string

	// The resource name to be displayed in protected resource metadata
	ResourceName *string

	// Individual options per route (simulated with interface{} for flexibility, assuming they are passed correctly to handlers)
	AuthorizationOptions      *handler.AuthorizationHandlerOptions
	ClientRegistrationOptions *handler.ClientRegistrationHandlerOptions
	RevocationOptions         *handler.RevocationHandlerOptions
	TokenOptions              *handler.TokenHandlerOptions
}

// AuthMetadataOptions holds configuration options for the MCP authentication metadata endpoints.
type AuthMetadataOptions struct {
	// OAuth Metadata as would be returned from the authorization server this MCP server relies on
	OAuthMetadata auth.OAuthMetadata

	// The url of the MCP server, for use in protected resource metadata
	ResourceServerUrl *url.URL

	// The url for documentation for the MCP server
	ServiceDocumentationUrl *url.URL

	// An optional list of scopes supported by this MCP server
	ScopesSupported []string

	// An optional resource name to display in resource metadata
	ResourceName *string
}

// checkIssuerUrl validates the issuer URL according to RFC 8414.
func checkIssuerUrl(issuer *url.URL) {
	// Technically RFC 8414 does not permit a localhost HTTPS exemption, but this will be necessary for ease of testing
	if issuer.Scheme != "https" && issuer.Hostname() != "localhost" && issuer.Hostname() != "127.0.0.1" {
		panic("Issuer URL must be HTTPS")
	}
	if issuer.Fragment != "" {
		panic("Issuer URL must not have a fragment: " + issuer.String())
	}
	if issuer.RawQuery != "" {
		panic("Issuer URL must not have a query string: " + issuer.String())
	}
}

// CreateOAuthMetadata generates the OAuth 2.0 Authorization Server Metadata.
func CreateOAuthMetadata(options struct {
	Provider                server.OAuthServerProvider
	IssuerUrl               *url.URL
	BaseUrl                 *url.URL
	ServiceDocumentationUrl *url.URL
	ScopesSupported         []string
}) auth.OAuthMetadata {
	issuer := options.IssuerUrl
	baseUrl := options.BaseUrl

	checkIssuerUrl(issuer)

	authorizationEndpoint := "/authorize"
	tokenEndpoint := "/token"

	// Check if the provider supports client registration and token revocation
	// This assumes the provider has methods or fields indicating support
	// For simplicity, we'll check if the relevant methods/store are non-nil
	// This part needs to be adapted based on your actual server.OAuthServerProvider interface
	var registrationEndpoint *string
	clientsStore := options.Provider.ClientsStore()
	if clientsStore != nil {
		endpoint := "/register"
		registrationEndpoint = &endpoint
	}

	var revocationEndpoint *string
	// Assuming there's a RevokeToken method on the provider interface
	// This check needs to be adapted based on your actual interface
	// if options.Provider.RevokeToken != nil { // Example check
	endpoint := "/revoke"
	revocationEndpoint = &endpoint
	// }

	var baseUrlForEndpoints *url.URL
	if baseUrl != nil {
		baseUrlForEndpoints = baseUrl
	} else {
		baseUrlForEndpoints = issuer
	}

	authEndpointUrl, _ := url.Parse(authorizationEndpoint)
	tokenEndpointUrl, _ := url.Parse(tokenEndpoint)

	metadata := auth.OAuthMetadata{
		Issuer:                            issuer.String(),
		AuthorizationEndpoint:             baseUrlForEndpoints.ResolveReference(authEndpointUrl).String(),
		ResponseTypesSupported:            []string{"code"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpoint:                     baseUrlForEndpoints.ResolveReference(tokenEndpointUrl).String(),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		ScopesSupported:                   options.ScopesSupported,
	}

	if options.ServiceDocumentationUrl != nil {
		serviceDoc := options.ServiceDocumentationUrl.String()
		metadata.ServiceDocumentation = &serviceDoc
	}

	if revocationEndpoint != nil {
		revEndpointUrl, _ := url.Parse(*revocationEndpoint)
		revEndpoint := baseUrlForEndpoints.ResolveReference(revEndpointUrl).String()
		metadata.RevocationEndpoint = &revEndpoint
		metadata.RevocationEndpointAuthMethodsSupported = []string{"client_secret_post"}
	}

	if registrationEndpoint != nil {
		regEndpointUrl, _ := url.Parse(*registrationEndpoint)
		regEndpoint := baseUrlForEndpoints.ResolveReference(regEndpointUrl).String()
		metadata.RegistrationEndpoint = &regEndpoint
	}

	return metadata
}

// McpAuthRouter sets up standard MCP authorization server endpoints, including dynamic client registration and token revocation
func McpAuthRouter(mux *http.ServeMux, options AuthRouterOptions) {
	oauthMetadata := CreateOAuthMetadata(struct {
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

	// 1) Authorization endpoint
	authorizationURL, _ := url.Parse(oauthMetadata.AuthorizationEndpoint)

	// Create authorization handler options
	authzOptions := handler.AuthorizationHandlerOptions{
		Provider: options.Provider,
	}
	if options.AuthorizationOptions != nil && options.AuthorizationOptions.RateLimit != nil {
		authzOptions.RateLimit = options.AuthorizationOptions.RateLimit
	}
	mux.Handle("GET "+authorizationURL.Path, handler.AuthorizationHandler(authzOptions))

	// 2) Token endpoint
	tokenURL, _ := url.Parse(oauthMetadata.TokenEndpoint)
	// Create token handler options
	tokenOptions := handler.TokenHandlerOptions{
		Provider: options.Provider,
	}
	if options.TokenOptions != nil && options.TokenOptions.RateLimit != nil {
		tokenOptions.RateLimit = options.TokenOptions.RateLimit
	}

	ginRouter := gin.New()
	ginRouter.POST(tokenURL.Path, handler.TokenHandler(tokenOptions))
	mux.Handle("POST "+tokenURL.Path, ginRouter)

	// 3) Metadata router
	issuerURL, _ := url.Parse(oauthMetadata.Issuer)
	McpAuthMetadataRouter(mux, AuthMetadataOptions{
		OAuthMetadata:           oauthMetadata,
		ResourceServerUrl:       issuerURL,
		ServiceDocumentationUrl: options.ServiceDocumentationUrl,
		ScopesSupported:         options.ScopesSupported,
		ResourceName:            options.ResourceName,
	})

	// 4) Dynamic client registration (optional)
	if oauthMetadata.RegistrationEndpoint != nil {
		registrationURL, _ := url.Parse(*oauthMetadata.RegistrationEndpoint)
		clientsStore := options.Provider.ClientsStore()

		regOpts := handler.ClientRegistrationHandlerOptions{
			ClientsStore: clientsStore,
		}

		// Use provided options or set defaults
		if options.ClientRegistrationOptions != nil {
			regOpts = *options.ClientRegistrationOptions
			regOpts.ClientsStore = clientsStore // Ensure the clients store is set
		} else {
			// Set default rate limiting
			regOpts.RateLimit = &handler.RateLimitConfig{
				WindowMs: 60000,
				Max:      10,
			}
		}

		ginRouter := gin.New()
		ginRouter.POST(registrationURL.Path, handler.ClientRegistrationHandler(regOpts))

		mux.Handle(registrationURL.Path, ginRouter)
	}

	// 5) Revocation endpoint (optional)
	if oauthMetadata.RevocationEndpoint != nil {
		revocationURL, _ := url.Parse(*oauthMetadata.RevocationEndpoint)

		// Create revocation handler options
		revOpts := handler.RevocationHandlerOptions{
			Provider: options.Provider,
		}
		if options.RevocationOptions != nil && options.RevocationOptions.RateLimit != nil {
			revOpts.RateLimit = options.RevocationOptions.RateLimit
		}

		ginRouter := gin.New()
		ginRouter.POST(revocationURL.Path, handler.RevocationHandler(revOpts))
		mux.Handle("POST "+revocationURL.Path, ginRouter)
	}
}

// McpAuthMetadataRouter sets up OAuth 2.0 metadata endpoints
func McpAuthMetadataRouter(mux *http.ServeMux, options AuthMetadataOptions) {
	issuerURL, _ := url.Parse(options.OAuthMetadata.Issuer)
	checkIssuerUrl(issuerURL)

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

	// Protected resource metadata endpoint
	mux.Handle("GET /.well-known/oauth-protected-resource",
		handler.MetadataHandler(protectedResourceMetadata))

	// Authorization server metadata endpoint (always added for backward compatibility)
	mux.Handle("GET /.well-known/oauth-authorization-server",
		handler.MetadataHandler(options.OAuthMetadata))
}

// GetOAuthProtectedResourceMetadataUrl constructs the OAuth 2.0 Protected Resource Metadata URL from a given server URL
// This will replace the path with the standard metadata endpoint
func GetOAuthProtectedResourceMetadataUrl(serverUrl *url.URL) string {
	metadataUrl, _ := url.Parse("/.well-known/oauth-protected-resource")
	return serverUrl.ResolveReference(metadataUrl).String()
}

// InstallMCPAuthRoutes convenience function to simplify route installation
func InstallMCPAuthRoutes(
	mux *http.ServeMux,
	issuerBaseURL string,     // = OAuthMetadata.issuer (e.g. https://auth.example.com)
	resourceServerURL string, // Your MCP service URL (e.g. https://api.example.com/mcp)
	clientsStore *server.OAuthClientsStoreInterface,
	provider server.OAuthServerProvider, // Your existing server provider interface
	scopesSupported []string,            // Can be nil
	resourceName *string,                // Can be nil
	serviceDocURL *string,               // Can be nil
) {
	issuerURL, _ := url.Parse(issuerBaseURL)
	var serviceDocumentationUrl *url.URL
	if serviceDocURL != nil {
		serviceDocumentationUrl, _ = url.Parse(*serviceDocURL)
	}

	options := AuthRouterOptions{
		Provider:                provider,
		IssuerUrl:               issuerURL,
		ServiceDocumentationUrl: serviceDocumentationUrl,
		ScopesSupported:         scopesSupported,
		ResourceName:            resourceName,
	}

	McpAuthRouter(mux, options)
}
