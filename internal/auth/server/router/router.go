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
	AuthorizationOptions      interface{} // Omit<AuthorizationHandlerOptions, "provider">
	ClientRegistrationOptions interface{} // Omit<ClientRegistrationHandlerOptions, "clientsStore">
	RevocationOptions         interface{} // Omit<RevocationHandlerOptions, "provider">
	TokenOptions              interface{} // Omit<TokenHandlerOptions, "provider">
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
	if clientsStore != nil && clientsStore.RegisterClient != nil {
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

// McpAuthRouter 严格对齐TypeScript版本的mcpAuthRouter函数
// 安装标准MCP授权服务器端点，包括动态客户端注册和令牌撤销
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

	// 1) 授权端点
	authorizationURL, _ := url.Parse(oauthMetadata.AuthorizationEndpoint)
	mux.Handle("GET "+authorizationURL.Path, handler.AuthorizeHandler(options.Provider))

	// 2) Token 端点
	tokenURL, _ := url.Parse(oauthMetadata.TokenEndpoint)
	mux.Handle("POST "+tokenURL.Path, handler.TokenHandler(options.Provider))

	// 3) 元数据路由器
	issuerURL, _ := url.Parse(oauthMetadata.Issuer)
	McpAuthMetadataRouter(mux, AuthMetadataOptions{
		OAuthMetadata:           oauthMetadata,
		ResourceServerUrl:       issuerURL,
		ServiceDocumentationUrl: options.ServiceDocumentationUrl,
		ScopesSupported:         options.ScopesSupported,
		ResourceName:            options.ResourceName,
	})

	// 4) 动态客户端注册（可选）
	if oauthMetadata.RegistrationEndpoint != nil {
		registrationURL, _ := url.Parse(*oauthMetadata.RegistrationEndpoint)
		clientsStore := options.Provider.ClientsStore()

		regOpts := handler.ClientRegistrationHandlerOptions{
			ClientsStore: clientsStore,
			RateLimit: &handler.RateLimitConfig{
				WindowMs: 60000,
				Max:      10,
			},
		}

		ginRouter := gin.New()
		ginRouter.POST(registrationURL.Path, handler.ClientRegistrationHandler(regOpts))

		mux.Handle(registrationURL.Path, ginRouter) // gin.Engine 实现了 http.Handler
	}

	// 5) 撤销端点（可选）
	if oauthMetadata.RevocationEndpoint != nil {
		revocationURL, _ := url.Parse(*oauthMetadata.RevocationEndpoint)
		mux.Handle("POST "+revocationURL.Path, handler.RevocationHandler(options.Provider))
	}
}

// McpAuthMetadataRouter 严格对齐TypeScript版本的mcpAuthMetadataRouter函数
func McpAuthMetadataRouter(mux *http.ServeMux, options AuthMetadataOptions) {
	issuerURL, _ := url.Parse(options.OAuthMetadata.Issuer)
	checkIssuerUrl(issuerURL)

	// 创建受保护资源元数据
	protectedResourceMetadata := auth.OAuthProtectedResourceMetadata{
		Resource: options.ResourceServerUrl.String(),
		AuthorizationServers: []string{
			options.OAuthMetadata.Issuer,
		},
		ScopesSupported: options.ScopesSupported,
	}

	// 添加可选字段
	if options.ResourceName != nil {
		protectedResourceMetadata.ResourceName = options.ResourceName
	}

	if options.ServiceDocumentationUrl != nil {
		resourceDoc := options.ServiceDocumentationUrl.String()
		protectedResourceMetadata.ResourceDocumentation = &resourceDoc
	}

	// 受保护资源元数据端点
	mux.Handle("GET /.well-known/oauth-protected-resource",
		handler.MetadataHandler(protectedResourceMetadata))

	// 授权服务器元数据端点（为了向后兼容总是添加）
	mux.Handle("GET /.well-known/oauth-authorization-server",
		handler.MetadataHandler(options.OAuthMetadata))
}

// GetOAuthProtectedResourceMetadataUrl 从给定的服务器URL构造OAuth 2.0受保护资源元数据URL的辅助函数
// 这会将路径替换为标准元数据端点
//
// 示例:
// GetOAuthProtectedResourceMetadataUrl(url.Parse('https://api.example.com/mcp'))
// 返回: 'https://api.example.com/.well-known/oauth-protected-resource'
func GetOAuthProtectedResourceMetadataUrl(serverUrl *url.URL) string {
	metadataUrl, _ := url.Parse("/.well-known/oauth-protected-resource")
	return serverUrl.ResolveReference(metadataUrl).String()
}

// InstallMCPAuthRoutes 便利函数，简化路由安装
func InstallMCPAuthRoutes(
	mux *http.ServeMux,
	issuerBaseURL string,     // = OAuthMetadata.issuer（例如 https://auth.example.com）
	resourceServerURL string, // 你的 MCP 服务 URL（例如 https://api.example.com/mcp）
	clientsStore *server.OAuthClientsStoreInterface,
	provider server.OAuthServerProvider, // 你已有的服务端 provider 接口
	scopesSupported []string,            // 可为 nil
	resourceName *string,                // 可为 nil
	serviceDocURL *string,               // 可为 nil
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
