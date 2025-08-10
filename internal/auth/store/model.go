package store

import "time"

// OAuthClient represents an OAuth 2.1 client according to RFC7591
type OAuthClient struct {
	ClientID                     string     `json:"client_id" db:"client_id"`
	ClientSecret                 string     `json:"client_secret,omitempty" db:"client_secret"`
	ClientName                   string     `json:"client_name,omitempty" db:"client_name"`
	RedirectURIs                 []string   `json:"redirect_uris" db:"redirect_uris"`
	GrantTypes                   []string   `json:"grant_types" db:"grant_types"`
	ResponseTypes                []string   `json:"response_types" db:"response_types"`
	Scope                        string     `json:"scope,omitempty" db:"scope"`
	TokenEndpointAuthMethod      string     `json:"token_endpoint_auth_method" db:"token_endpoint_auth_method"`
	JWKSUri                      string     `json:"jwks_uri,omitempty" db:"jwks_uri"`
	JWKS                         string     `json:"jwks,omitempty" db:"jwks"`
	SoftwareID                   string     `json:"software_id,omitempty" db:"software_id"`
	SoftwareVersion              string     `json:"software_version,omitempty" db:"software_version"`
	ClientURI                    string     `json:"client_uri,omitempty" db:"client_uri"`
	LogoURI                      string     `json:"logo_uri,omitempty" db:"logo_uri"`
	TosURI                       string     `json:"tos_uri,omitempty" db:"tos_uri"`
	PolicyURI                    string     `json:"policy_uri,omitempty" db:"policy_uri"`
	Contacts                     []string   `json:"contacts,omitempty" db:"contacts"`
	CreatedAt                    time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt                    time.Time  `json:"updated_at" db:"updated_at"`
	ExpiresAt                    *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	ClientIDIssuedAt             time.Time  `json:"client_id_issued_at" db:"client_id_issued_at"`
	ClientSecretExpiresAt        *time.Time `json:"client_secret_expires_at,omitempty" db:"client_secret_expires_at"`
	ApplicationType              string     `json:"application_type,omitempty" db:"application_type"`
	SubjectType                  string     `json:"subject_type,omitempty" db:"subject_type"`
	IDTokenSignedResponseAlg     string     `json:"id_token_signed_response_alg,omitempty" db:"id_token_signed_response_alg"`
	IDTokenEncryptedResponseAlg  string     `json:"id_token_encrypted_response_alg,omitempty" db:"id_token_encrypted_response_alg"`
	IDTokenEncryptedResponseEnc  string     `json:"id_token_encrypted_response_enc,omitempty" db:"id_token_encrypted_response_enc"`
	UserinfoSignedResponseAlg    string     `json:"userinfo_signed_response_alg,omitempty" db:"userinfo_signed_response_alg"`
	UserinfoEncryptedResponseAlg string     `json:"userinfo_encrypted_response_alg,omitempty" db:"userinfo_encrypted_response_alg"`
	UserinfoEncryptedResponseEnc string     `json:"userinfo_encrypted_response_enc,omitempty" db:"userinfo_encrypted_response_enc"`
	RequestObjectSigningAlg      string     `json:"request_object_signing_alg,omitempty" db:"request_object_signing_alg"`
	RequestObjectEncryptionAlg   string     `json:"request_object_encryption_alg,omitempty" db:"request_object_encryption_alg"`
	RequestObjectEncryptionEnc   string     `json:"request_object_encryption_enc,omitempty" db:"request_object_encryption_enc"`
	DefaultMaxAge                int        `json:"default_max_age,omitempty" db:"default_max_age"`
	RequireAuthTime              bool       `json:"require_auth_time,omitempty" db:"require_auth_time"`
	DefaultACRValues             []string   `json:"default_acr_values,omitempty" db:"default_acr_values"`
	InitiateLoginURI             string     `json:"initiate_login_uri,omitempty" db:"initiate_login_uri"`
	RequestURIs                  []string   `json:"request_uris,omitempty" db:"request_uris"`
}

// ClientRegistrationRequest represents dynamic client registration request
type ClientRegistrationRequest struct {
	RedirectURIs                 []string `json:"redirect_uris,omitempty"`
	ResponseTypes                []string `json:"response_types,omitempty"`
	GrantTypes                   []string `json:"grant_types,omitempty"`
	ApplicationType              string   `json:"application_type,omitempty"`
	Contacts                     []string `json:"contacts,omitempty"`
	ClientName                   string   `json:"client_name,omitempty"`
	LogoURI                      string   `json:"logo_uri,omitempty"`
	ClientURI                    string   `json:"client_uri,omitempty"`
	PolicyURI                    string   `json:"policy_uri,omitempty"`
	TosURI                       string   `json:"tos_uri,omitempty"`
	JWKSUri                      string   `json:"jwks_uri,omitempty"`
	JWKS                         string   `json:"jwks,omitempty"`
	SectorIdentifierURI          string   `json:"sector_identifier_uri,omitempty"`
	SubjectType                  string   `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg     string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg  string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string   `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedResponseAlg    string   `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg string   `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc string   `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string   `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg   string   `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc   string   `json:"request_object_encryption_enc,omitempty"`
	TokenEndpointAuthMethod      string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg  string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                int      `json:"default_max_age,omitempty"`
	RequireAuthTime              bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues             []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI             string   `json:"initiate_login_uri,omitempty"`
	RequestURIs                  []string `json:"request_uris,omitempty"`
	Scope                        string   `json:"scope,omitempty"`
}

// ClientRegistrationResponse represents dynamic client registration response
type ClientRegistrationResponse struct {
	ClientID                     string   `json:"client_id"`
	ClientSecret                 string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt             int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt        *int64   `json:"client_secret_expires_at,omitempty"`
	RedirectURIs                 []string `json:"redirect_uris,omitempty"`
	ResponseTypes                []string `json:"response_types,omitempty"`
	GrantTypes                   []string `json:"grant_types,omitempty"`
	ApplicationType              string   `json:"application_type,omitempty"`
	Contacts                     []string `json:"contacts,omitempty"`
	ClientName                   string   `json:"client_name,omitempty"`
	LogoURI                      string   `json:"logo_uri,omitempty"`
	ClientURI                    string   `json:"client_uri,omitempty"`
	PolicyURI                    string   `json:"policy_uri,omitempty"`
	TosURI                       string   `json:"tos_uri,omitempty"`
	JWKSUri                      string   `json:"jwks_uri,omitempty"`
	JWKS                         string   `json:"jwks,omitempty"`
	SubjectType                  string   `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg     string   `json:"id_token_signed_response_alg,omitempty"`
	IDTokenEncryptedResponseAlg  string   `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc  string   `json:"id_token_encrypted_response_enc,omitempty"`
	UserinfoSignedResponseAlg    string   `json:"userinfo_signed_response_alg,omitempty"`
	UserinfoEncryptedResponseAlg string   `json:"userinfo_encrypted_response_alg,omitempty"`
	UserinfoEncryptedResponseEnc string   `json:"userinfo_encrypted_response_enc,omitempty"`
	RequestObjectSigningAlg      string   `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg   string   `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc   string   `json:"request_object_encryption_enc,omitempty"`
	TokenEndpointAuthMethod      string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg  string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	DefaultMaxAge                int      `json:"default_max_age,omitempty"`
	RequireAuthTime              bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues             []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI             string   `json:"initiate_login_uri,omitempty"`
	RequestURIs                  []string `json:"request_uris,omitempty"`
	RegistrationAccessToken      string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI        string   `json:"registration_client_uri,omitempty"`
	Scope                        string   `json:"scope,omitempty"`
}
