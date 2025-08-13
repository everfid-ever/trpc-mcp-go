package auth

import "net/http"

// OAuthClientMetadata 定义OAuth客户端元数据的结构，基于OAuth 2.1规范。
// Defines the structure for OAuth client metadata, based on OAuth 2.1 specification.
type OAuthClientMetadata struct {
	// RedirectURIs 是客户端注册的重定向URI列表，必须包含有效的URL。
	// 验证规则：每个URI必须可以通过 net/url.Parse 解析为有效URL。
	// RedirectURIs is a list of redirect URIs for the client, must contain valid URLs.
	// Validation rule: Each URI must be parseable by net/url.Parse.
	RedirectURIs []string `json:"redirect_uris"`

	// TokenEndpointAuthMethod 是令牌端点认证方法，可选。
	// TokenEndpointAuthMethod is the authentication method for the token endpoint, optional.
	TokenEndpointAuthMethod *string `json:"token_endpoint_auth_method,omitempty"`

	// GrantTypes 是支持的授权类型列表，可选。
	// GrantTypes is a list of supported grant types, optional.
	GrantTypes []string `json:"grant_types,omitempty"`

	// ResponseTypes 是支持的响应类型列表，可选。
	// ResponseTypes is a list of supported response types, optional.
	ResponseTypes []string `json:"response_types,omitempty"`

	// ClientName 是客户端的名称，可选。
	// ClientName is the name of the client, optional.
	ClientName *string `json:"client_name,omitempty"`

	// ClientURI 是客户端的URI，可选。
	// ClientURI is the URI of the client, optional.
	ClientURI *string `json:"client_uri,omitempty"`

	// LogoURI 是客户端的Logo URI，可选。
	// LogoURI is the URI of the client's logo, optional.
	LogoURI *string `json:"logo_uri,omitempty"`

	// Scope 是客户端请求的权限范围（以空格分隔的字符串），可选。
	// Scope is the requested scope for the client (space-separated string), optional.
	Scope *string `json:"scope,omitempty"`

	// Contacts 是客户端的联系人列表（通常为邮箱地址），可选。
	// Contacts is a list of contact information for the client (typically email addresses), optional.
	Contacts []string `json:"contacts,omitempty"`

	// TosURI 是客户端的服务条款URI，可选。
	// TosURI is the URI of the client's terms of service, optional.
	TosURI *string `json:"tos_uri,omitempty"`

	// PolicyURI 是客户端的隐私策略URI，可选。
	// PolicyURI is the URI of the client's privacy policy, optional.
	PolicyURI *string `json:"policy_uri,omitempty"`

	// JwksURI 是客户端的JSON Web Key Set URI，可选。
	// JwksURI is the URI of the client's JSON Web Key Set, optional.
	JwksURI *string `json:"jwks_uri,omitempty"`

	// Jwks 是客户端的JSON Web Key Set，任意类型，可选。
	// Jwks is the client's JSON Web Key Set, any type, optional.
	Jwks interface{} `json:"jwks,omitempty"`

	// SoftwareID 是客户端的软件ID，可选。
	// SoftwareID is the software ID of the client, optional.
	SoftwareID *string `json:"software_id,omitempty"`

	// SoftwareVersion 是客户端的软件版本，可选。
	// SoftwareVersion is the software version of the client, optional.
	SoftwareVersion *string `json:"software_version,omitempty"`

	// SoftwareStatement 是客户端的软件声明，可选。
	// SoftwareStatement is the software statement of the client, optional.
	SoftwareStatement *string `json:"software_statement,omitempty"`
}

// OAuthClientInformation 定义RFC 7591 OAuth 2.0动态客户端注册的客户端信息。(OAuth 2.1沿用)
// Defines RFC 7591 OAuth 2.0 Dynamic Client Registration client information.(OAuth 2.1 follows)
type OAuthClientInformation struct {
	// ClientID 是客户端的唯一标识符，必须提供。
	// 验证规则：必须是非空字符串。
	// ClientID is the unique identifier for the client, required.
	// Validation rule: Must be a non-empty string.
	ClientID string `json:"client_id"`

	// ClientSecret 是客户端的密钥，可选。
	// 验证规则：如果提供，必须是非空字符串。
	// ClientSecret is the client's secret, optional.
	// Validation rule: If provided, must be a non-empty string.
	ClientSecret string `json:"client_secret,omitempty"`

	// ClientIDIssuedAt 是客户端ID的颁发时间（自Unix纪元以来的秒数），可选。
	// 验证规则：如果提供，必须是有效的Unix时间戳（数字）。
	// ClientIDIssuedAt is the issuance time of the client ID (seconds since Unix epoch), optional.
	// Validation rule: If provided, must be a valid Unix timestamp (number).
	ClientIDIssuedAt int64 `json:"client_id_issued_at,omitempty"`

	// ClientSecretExpiresAt 是客户端密钥的过期时间（自Unix纪元以来的秒数），可选。
	// 验证规则：如果提供，必须是有效的Unix时间戳（数字）。
	// ClientSecretExpiresAt is the expiration time of the client secret (seconds since Unix epoch), optional.
	// Validation rule: If provided, must be a valid Unix timestamp (number).
	ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`
}

type OAuthClientInformationFull struct {
	OAuthClientMetadata
	OAuthClientInformation
}

// OAuthTokens 定义OAuth 2.1令牌响应的结构。
// Defines the OAuth 2.1 token response.
type OAuthTokens struct {
	// AccessToken 是访问令牌，必须提供。
	// 验证规则：必须是非空字符串。
	// AccessToken is the access token, required.
	// Validation rule: Must be a non-empty string.
	AccessToken string `json:"access_token"`

	// IDToken 是OpenID Connect的ID令牌，可选。
	// 在OAuth 2.1中可选，但在OpenID Connect中必需。
	// 验证规则：如果提供，必须是非空字符串。
	// IDToken is the OpenID Connect ID token, optional.
	// Optional for OAuth 2.1, but necessary in OpenID Connect.
	// Validation rule: If provided, must be a non-empty string.
	IDToken *string `json:"id_token,omitempty"`

	// TokenType 是令牌类型（例如"Bearer"），必须提供。
	// 验证规则：必须是非空字符串。
	// TokenType is the token type (e.g., "Bearer"), required.
	// Validation rule: Must be a non-empty string.
	TokenType string `json:"token_type"`

	// ExpiresIn 是访问令牌的过期时间（以秒为单位），可选。
	// 验证规则：如果提供，必须是正整数。
	// ExpiresIn is the expiration time of the access token (in seconds), optional.
	// Validation rule: If provided, must be a positive integer.
	ExpiresIn *int64 `json:"expires_in,omitempty"`

	// Scope 是授权的权限范围（以空格分隔的字符串），可选。
	// 验证规则：如果提供，必须是非空字符串。
	// Scope is the authorized scope (space-separated string), optional.
	// Validation rule: If provided, must be a non-empty string.
	Scope *string `json:"scope,omitempty"`

	// RefreshToken 是刷新令牌，可选。
	// 验证规则：如果提供，必须是非空字符串。
	// RefreshToken is the refresh token, optional.
	// Validation rule: If provided, must be a non-empty string.
	RefreshToken *string `json:"refresh_token,omitempty"`
}

type OAuthTokenRevocationRequest struct {
	Token         string `json:"token"`                     //要撤销的令牌 / token to revoke
	TokenTypeHint string `json:"token_type_hint,omitempty"` //令牌类型提示，可选 / token type hint, optional
}

// AuthorizationServerMetadata 表示授权服务器的元数据，可以是OAuth 2.0或OpenID Connect元数据。
// Represents the metadata of an authorization server, which can be either OAuth 2.0 or OpenID Connect metadata.
type AuthorizationServerMetadata interface {
	// GetIssuer 返回服务器的发行者标识符。
	// Returns the issuer identifier for the authorization server.
	GetIssuer() string

	// GetAuthorizationEndpoint 返回授权端点URL。
	// Returns the authorization endpoint URL.
	GetAuthorizationEndpoint() string

	// GetTokenEndpoint 返回令牌端点URL。
	// Returns the token endpoint URL.
	GetTokenEndpoint() string

	// GetResponseTypesSupported 返回服务器支持的响应类型。
	// Returns the response types supported by the server.
	GetResponseTypesSupported() []string
}

// OAuthMetadata 定义OAuth 2.0授权服务器元数据，符合RFC 8414。
type OAuthMetadata struct {
	Issuer                                             string   `json:"issuer"`
	AuthorizationEndpoint                              string   `json:"authorization_endpoint"`
	TokenEndpoint                                      string   `json:"token_endpoint"`
	RegistrationEndpoint                               *string  `json:"registration_endpoint,omitempty"`
	ScopesSupported                                    []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                             []string `json:"response_types_supported"`
	ResponseModesSupported                             []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                                []string `json:"grant_types_supported,omitempty"`
	TokenEndpointAuthMethodsSupported                  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported         []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	ServiceDocumentation                               *string  `json:"service_documentation,omitempty"`
	RevocationEndpoint                                 *string  `json:"revocation_endpoint,omitempty"`
	RevocationEndpointAuthMethodsSupported             []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	RevocationEndpointAuthSigningAlgValuesSupported    []string `json:"revocation_endpoint_auth_signing_alg_values_supported,omitempty"`
	IntrospectionEndpoint                              *string  `json:"introspection_endpoint,omitempty"`
	IntrospectionEndpointAuthMethodsSupported          []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthSigningAlgValuesSupported []string `json:"introspection_endpoint_auth_signing_alg_values_supported,omitempty"`
	CodeChallengeMethodsSupported                      []string `json:"code_challenge_methods_supported,omitempty"`
}

func (m OAuthMetadata) GetIssuer() string {
	return m.Issuer
}

func (m OAuthMetadata) GetAuthorizationEndpoint() string {
	return m.AuthorizationEndpoint
}

func (m OAuthMetadata) GetTokenEndpoint() string {
	return m.TokenEndpoint
}

func (m OAuthMetadata) GetResponseTypesSupported() []string {
	return m.ResponseTypesSupported
}

// OpenIdProviderMetadata 定义OpenID Connect Discovery 1.0提供者元数据。
type OpenIdProviderMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           *string  `json:"userinfo_endpoint,omitempty"`
	JwksURI                                    string   `json:"jwks_uri"`
	RegistrationEndpoint                       *string  `json:"registration_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	AcrValuesSupported                         []string `json:"acr_values_supported,omitempty"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	IdTokenEncryptionAlgValuesSupported        []string `json:"id_token_encryption_alg_values_supported,omitempty"`
	IdTokenEncryptionEncValuesSupported        []string `json:"id_token_encryption_enc_values_supported,omitempty"`
	UserinfoSigningAlgValuesSupported          []string `json:"userinfo_signing_alg_values_supported,omitempty"`
	UserinfoEncryptionAlgValuesSupported       []string `json:"userinfo_encryption_alg_values_supported,omitempty"`
	UserinfoEncryptionEncValuesSupported       []string `json:"userinfo_encryption_enc_values_supported,omitempty"`
	RequestObjectSigningAlgValuesSupported     []string `json:"request_object_signing_alg_values_supported,omitempty"`
	RequestObjectEncryptionAlgValuesSupported  []string `json:"request_object_encryption_alg_values_supported,omitempty"`
	RequestObjectEncryptionEncValuesSupported  []string `json:"request_object_encryption_enc_values_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
	DisplayValuesSupported                     []string `json:"display_values_supported,omitempty"`
	ClaimTypesSupported                        []string `json:"claim_types_supported,omitempty"`
	ClaimsSupported                            []string `json:"claims_supported,omitempty"`
	ServiceDocumentation                       *string  `json:"service_documentation,omitempty"`
	ClaimsLocalesSupported                     []string `json:"claims_locales_supported,omitempty"`
	UiLocalesSupported                         []string `json:"ui_locales_supported,omitempty"`
	ClaimsParameterSupported                   *bool    `json:"claims_parameter_supported,omitempty"`
	RequestParameterSupported                  *bool    `json:"request_parameter_supported,omitempty"`
	RequestUriParameterSupported               *bool    `json:"request_uri_parameter_supported,omitempty"`
	RequireRequestUriRegistration              *bool    `json:"require_request_uri_registration,omitempty"`
	OpPolicyUri                                *string  `json:"op_policy_uri,omitempty"`
	OpTosUri                                   *string  `json:"op_tos_uri,omitempty"`
}

func (m OpenIdProviderMetadata) GetIssuer() string {
	return m.Issuer
}

func (m OpenIdProviderMetadata) GetAuthorizationEndpoint() string {
	return m.AuthorizationEndpoint
}

func (m OpenIdProviderMetadata) GetTokenEndpoint() string {
	return m.TokenEndpoint
}

func (m OpenIdProviderMetadata) GetResponseTypesSupported() []string {
	return m.ResponseTypesSupported
}

// OpenIdProviderDiscoveryMetadata 定义OpenID Connect发现元数据，合并OAuth 2.0字段。
type OpenIdProviderDiscoveryMetadata struct {
	OpenIdProviderMetadata                 // 嵌入OpenID Connect元数据
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

func (m OpenIdProviderDiscoveryMetadata) GetIssuer() string {
	return m.OpenIdProviderMetadata.Issuer
}

func (m OpenIdProviderDiscoveryMetadata) GetAuthorizationEndpoint() string {
	return m.OpenIdProviderMetadata.AuthorizationEndpoint
}

func (m OpenIdProviderDiscoveryMetadata) GetTokenEndpoint() string {
	return m.OpenIdProviderMetadata.TokenEndpoint
}

func (m OpenIdProviderDiscoveryMetadata) GetResponseTypesSupported() []string {
	return m.OpenIdProviderMetadata.ResponseTypesSupported
}

type FetchFunc func(url string, req *http.Request) (*http.Response, error)
