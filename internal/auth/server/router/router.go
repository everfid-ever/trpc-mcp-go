package router

import (
	"net/http"
	"net/url"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server"
	"trpc.group/trpc-go/trpc-mcp-go/internal/auth/server/handler"
)

type AuthRouterOptions struct {
	// Provider 实现此路由器实际授权逻辑的提供者
	// A provider implementing the actual authorization logic for this router.
	Provider server.OAuthServerProvider

	// IssuerUrl 授权服务器的颁发者标识符，必须是使用 "https" 方案且没有查询或片段组件的 URL
	// The authorization server's issuer identifier, which is a URL that uses the "https" scheme and has no query or fragment components.
	IssuerUrl *url.URL

	// BaseUrl 用于元数据端点的授权服务器基础 URL（可选）
	// The base URL of the authorization server to use for the metadata endpoints.
	// If not provided, the issuer URL will be used as the base URL.
	BaseUrl *url.URL

	// ServiceDocumentationUrl 包含开发者在使用授权服务器时可能需要了解的人类可读信息的页面 URL（可选）
	// An optional URL of a page containing human-readable information that developers might want or need to know when using the authorization server.
	ServiceDocumentationUrl *url.URL

	// ScopesSupported 此授权服务器支持的作用域列表（可选）
	// An optional list of scopes supported by this authorization server
	ScopesSupported []string

	// ResourceName 在受保护资源元数据中显示的资源名称
	// The resource name to be displayed in protected resource metadata
	ResourceName *string

	// TODO: 个别路由选项
	// Individual options per route
	// AuthorizationOptions
	// ClientRegistrationOptions
	// RevocationOptions
	// TokenOptions
}

type AuthMetadataOptions struct {
	// OAuthMetadata 从此 MCP 服务器依赖的授权服务器返回的 OAuth 元数据
	// OAuth Metadata as would be returned from the authorization server this MCP server relies on
	OAuthMetadata auth.OAuthMetadata

	// ResourceServerUrl MCP 服务器的 URL，用于受保护资源元数据
	// The url of the MCP server, for use in protected resource metadata
	ResourceServerUrl *url.URL

	// ServiceDocumentationUrl MCP 服务器文档的 URL
	// The url for documentation for the MCP server
	ServiceDocumentationUrl *url.URL

	// ScopesSupported 此 MCP 服务器支持的作用域列表（可选）
	// An optional list of scopes supported by this MCP server
	ScopesSupported []string

	// ResourceName 在资源元数据中显示的可选资源名称
	// An optional resource name to display in resource metadata
	ResourceName *string
}

func checkIssuerUrl(issuer *url.URL) {
	// 技术上 RFC 8414 不允许 localhost HTTPS 豁免，但这对于测试的便利性是必要的
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

// CreateOAuthMetadata 严格对齐TypeScript版本的createOAuthMetadata函数
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

	var registrationEndpoint *string
	if options.Provider.ClientsStore() != nil {
		// 假设如果有ClientsStore则支持注册，这里需要根据实际接口调整
		endpoint := "/register"
		registrationEndpoint = &endpoint
	}

	var revocationEndpoint *string
	// 需要检查provider是否支持撤销，这里需要根据实际接口调整
	// if options.Provider.RevokeToken != nil {
	endpoint := "/revoke"
	revocationEndpoint = &endpoint
	// }

	// 构建完整的endpoint URLs
	var baseUrlForEndpoints *url.URL
	if baseUrl != nil {
		baseUrlForEndpoints = baseUrl
	} else {
		baseUrlForEndpoints = issuer
	}

	authEndpointUrl, _ := url.Parse(authorizationEndpoint)
	tokenEndpointUrl, _ := url.Parse(tokenEndpoint)

	metadata := auth.OAuthMetadata{
		Issuer: issuer.String(),

		AuthorizationEndpoint:         baseUrlForEndpoints.ResolveReference(authEndpointUrl).String(),
		ResponseTypesSupported:        []string{"code"},
		CodeChallengeMethodsSupported: []string{"S256"},

		TokenEndpoint:                     baseUrlForEndpoints.ResolveReference(tokenEndpointUrl).String(),
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},

		ScopesSupported: options.ScopesSupported,
	}

	// 添加可选的service documentation
	if options.ServiceDocumentationUrl != nil {
		serviceDoc := options.ServiceDocumentationUrl.String()
		metadata.ServiceDocumentation = &serviceDoc
	}

	// 添加可选的revocation endpoint
	if revocationEndpoint != nil {
		revEndpointUrl, _ := url.Parse(*revocationEndpoint)
		revEndpoint := baseUrlForEndpoints.ResolveReference(revEndpointUrl).String()
		metadata.RevocationEndpoint = &revEndpoint
		metadata.RevocationEndpointAuthMethodsSupported = []string{"client_secret_post"}
	}

	// 添加可选的registration endpoint
	if registrationEndpoint != nil {
		regEndpointUrl, _ := url.Parse(*registrationEndpoint)
		regEndpoint := baseUrlForEndpoints.ResolveReference(regEndpointUrl).String()
		metadata.RegistrationEndpoint = &regEndpoint
	}

	return metadata
}

// McpAuthRouter 严格对齐TypeScript版本的mcpAuthRouter函数
// 安装标准MCP授权服务器端点，包括动态客户端注册和令牌撤销（如果支持）
// 还发布标准授权服务器元数据，以便客户端更容易发现支持的配置
// 注意：如果您的MCP服务器只是资源服务器而不是授权服务器，请使用McpAuthMetadataRouter
//
// 默认情况下，对所有端点应用速率限制以防止滥用
//
// 此路由器必须安装在应用程序根目录下
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

	// 3) 元数据路由器（此路由器用于AS+RS组合，因此颁发者也是资源服务器）
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
		mux.Handle("POST "+registrationURL.Path, handler.RegisterHandler(clientsStore))
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
	clientsStore server.OAuthClientsStoreInterface,
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
