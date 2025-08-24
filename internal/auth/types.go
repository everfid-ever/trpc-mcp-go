package auth

import "net/http"

// OAuthClientMetadata defines RFC 7591 OAuth 2.0 Dynamic Client Registration metadata
type OAuthClientMetadata struct {
	RedirectURIs            []string    `json:"redirect_uris"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string    `json:"grant_types,omitempty"`
	ResponseTypes           []string    `json:"response_types,omitempty"`
	ClientName              *string     `json:"client_name,omitempty"`
	ClientURI               *string     `json:"client_uri,omitempty"`
	LogoURI                 *string     `json:"logo_uri,omitempty"`
	Scope                   *string     `json:"scope,omitempty"`
	Contacts                []string    `json:"contacts,omitempty"`
	TosURI                  *string     `json:"tos_uri,omitempty"`
	PolicyURI               *string     `json:"policy_uri,omitempty"`
	JwksURI                 *string     `json:"jwks_uri,omitempty"`
	Jwks                    interface{} `json:"jwks,omitempty"`
	SoftwareID              *string     `json:"software_id,omitempty"`
	SoftwareVersion         *string     `json:"software_version,omitempty"`
	SoftwareStatement       *string     `json:"software_statement,omitempty"`
}

// OAuthClientInformation defines RFC 7591 OAuth 2.0 Dynamic Client Registration client information
type OAuthClientInformation struct {
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      *int64 `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`
}

// OAuthClientInformationFull defines RFC 7591 OAuth 2.0 Dynamic Client Registration full response
type OAuthClientInformationFull struct {
	OAuthClientMetadata
	OAuthClientInformation
}

// OAuthProtectedResourceMetadata defines RFC 9728 OAuth Protected Resource Metadata
type OAuthProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	JWKSURI                *string  `json:"jwks_uri,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgs    []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceName           *string  `json:"resource_name,omitempty"`
	ResourceDocumentation  *string  `json:"resource_documentation,omitempty"`
	ResourcePolicyURI      *string  `json:"resource_policy_uri,omitempty"`
	ResourceTOSURI         *string  `json:"resource_tos_uri,omitempty"`
	TLSCertBoundAT         *bool    `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	AuthzDetailsTypes      []string `json:"authorization_details_types_supported,omitempty"`
	DPoPSigningAlgs        []string `json:"dpop_signing_alg_values_supported,omitempty"`
	DPoPBoundATRequired    *bool    `json:"dpop_bound_access_tokens_required,omitempty"`
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

	// GetGrantTypesSupported 返回服务器支持的授权类型。
	// Returns the grant types supported by the server.
	GetGrantTypesSupported() []string

	// GetTokenEndpointAuthMethodsSupported 返回令牌端点支持的客户端认证方法。
	// Returns the client authentication methods supported by the token endpoint.
	GetTokenEndpointAuthMethodsSupported() []string
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

func (m OAuthMetadata) GetGrantTypesSupported() []string {
	return m.GrantTypesSupported
}

func (m OAuthMetadata) GetTokenEndpointAuthMethodsSupported() []string {
	return m.TokenEndpointAuthMethodsSupported
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

func (m OpenIdProviderMetadata) GetGrantTypesSupported() []string {
	return m.GrantTypesSupported
}

func (m OpenIdProviderMetadata) GetTokenEndpointAuthMethodsSupported() []string {
	return m.TokenEndpointAuthMethodsSupported
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

func (m OpenIdProviderDiscoveryMetadata) GetGrantTypesSupported() []string {
	return m.OpenIdProviderMetadata.GrantTypesSupported
}

func (m OpenIdProviderDiscoveryMetadata) GetTokenEndpointAuthMethodsSupported() []string {
	return m.OpenIdProviderMetadata.TokenEndpointAuthMethodsSupported
}

type FetchFunc func(url string, req *http.Request) (*http.Response, error)
