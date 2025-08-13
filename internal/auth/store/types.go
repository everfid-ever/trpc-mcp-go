package store

// OAuthClientMetadata RFC 7591 OAuth 2.0 Dynamic Client Registration metadata
type OAuthClientMetadata struct {
	RedirectUris            []string    `json:"redirect_uris"`
	TokenEndpointAuthMethod string      `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string    `json:"grant_types,omitempty"`
	ResponseTypes           []string    `json:"response_types,omitempty"`
	ClientName              string      `json:"client_name,omitempty"`
	ClientURI               string      `json:"client_uri,omitempty"`
	LogoURI                 string      `json:"logo_uri,omitempty"`
	Scope                   string      `json:"scope,omitempty"`
	Contacts                []string    `json:"contacts,omitempty"`
	TosURI                  string      `json:"tos_uri,omitempty"`
	PolicyURI               string      `json:"policy_uri,omitempty"`
	JwksURI                 string      `json:"jwks_uri,omitempty"`
	Jwks                    interface{} `json:"jwks,omitempty"`
	SoftwareID              string      `json:"software_id,omitempty"`
	SoftwareVersion         string      `json:"software_version,omitempty"`
	SoftwareStatement       string      `json:"software_statement,omitempty"`
}

// OAuthClientInformation RFC 7591 OAuth 2.0 Dynamic Client Registration client information
type OAuthClientInformation struct {
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      *int64 `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt *int64 `json:"client_secret_expires_at,omitempty"`
}

// OAuthClientInformationFull RFC 7591 OAuth 2.0 Dynamic Client Registration full response
type OAuthClientInformationFull struct {
	OAuthClientMetadata
	OAuthClientInformation
}

// OAuthClientRegistrationError RFC 7591 OAuth 2.0 Dynamic Client Registration error response
type OAuthClientRegistrationError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
