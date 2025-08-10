package store

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
)

// ClientValidator validates OAuth client data
type ClientValidator struct{}

// NewClientValidator creates a new client validator
func NewClientValidator() *ClientValidator {
	return &ClientValidator{}
}

var (
	// URI validation regex
	uriRegex = regexp.MustCompile(`^https?://[^\s/$.?#].[^\s]*$`)

	// Supported grant types
	supportedGrantTypes = map[string]bool{
		"authorization_code": true,
		"client_credentials": true,
		"refresh_token":      true,
		"urn:ietf:params:oauth:grant-type:device_code": true,
	}

	// Supported response types
	supportedResponseTypes = map[string]bool{
		"code": true,
	}

	// Supported token endpoint auth methods
	supportedAuthMethods = map[string]bool{
		"client_secret_basic": true,
		"client_secret_post":  true,
		"client_secret_jwt":   true,
		"private_key_jwt":     true,
		"none":                true,
	}
)

// ValidateRegistrationRequest validates client registration request
func (v *ClientValidator) ValidateRegistrationRequest(req *ClientRegistrationRequest) error {
	// Validate redirect URIs
	if len(req.RedirectURIs) == 0 {
		return errors.New("redirect_uris is required")
	}

	for _, uri := range req.RedirectURIs {
		if uri == "" {
			return errors.New("redirect_uri cannot be empty")
		}

		// Parse URI
		parsedURI, err := url.Parse(uri)
		if err != nil {
			return fmt.Errorf("invalid redirect_uri: %s", uri)
		}

		// Check for fragments (not allowed)
		if parsedURI.Fragment != "" {
			return fmt.Errorf("redirect_uri cannot contain fragment: %s", uri)
		}

		// For public clients, require HTTPS or localhost
		if req.TokenEndpointAuthMethod == "none" {
			if parsedURI.Scheme != "https" && parsedURI.Hostname() != "localhost" && parsedURI.Hostname() != "127.0.0.1" {
				return fmt.Errorf("public clients must use HTTPS or localhost: %s", uri)
			}
		}
	}

	// Validate grant types
	for _, grantType := range req.GrantTypes {
		if !supportedGrantTypes[grantType] {
			return fmt.Errorf("unsupported grant_type: %s", grantType)
		}
	}

	// Validate response types
	for _, responseType := range req.ResponseTypes {
		if !supportedResponseTypes[responseType] {
			return fmt.Errorf("unsupported response_type: %s", responseType)
		}
	}

	// Validate token endpoint auth method
	if req.TokenEndpointAuthMethod != "" && !supportedAuthMethods[req.TokenEndpointAuthMethod] {
		return fmt.Errorf("unsupported token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod)
	}

	// Validate URIs
	uriFields := []struct {
		name string
		uri  string
	}{
		{"client_uri", req.ClientURI},
		{"logo_uri", req.LogoURI},
		{"tos_uri", req.TosURI},
		{"policy_uri", req.PolicyURI},
		{"jwks_uri", req.JWKSUri},
		{"initiate_login_uri", req.InitiateLoginURI},
	}

	for _, field := range uriFields {
		if field.uri != "" && !uriRegex.MatchString(field.uri) {
			return fmt.Errorf("invalid %s: %s", field.name, field.uri)
		}
	}

	// Validate request URIs
	for _, reqURI := range req.RequestURIs {
		if !uriRegex.MatchString(reqURI) {
			return fmt.Errorf("invalid request_uri: %s", reqURI)
		}
	}

	// Validate application type
	if req.ApplicationType != "" && req.ApplicationType != "web" && req.ApplicationType != "native" {
		return fmt.Errorf("invalid application_type: %s", req.ApplicationType)
	}

	// Validate subject type
	if req.SubjectType != "" && req.SubjectType != "public" && req.SubjectType != "pairwise" {
		return fmt.Errorf("invalid subject_type: %s", req.SubjectType)
	}

	return nil
}

// ValidateClient validates OAuth client data
func (v *ClientValidator) ValidateClient(client *OAuthClient) error {
	if client.ClientID == "" {
		return errors.New("client_id is required")
	}

	if len(client.RedirectURIs) == 0 {
		return errors.New("redirect_uris is required")
	}

	// Validate redirect URIs
	for _, uri := range client.RedirectURIs {
		if uri == "" {
			return errors.New("redirect_uri cannot be empty")
		}

		parsedURI, err := url.Parse(uri)
		if err != nil {
			return fmt.Errorf("invalid redirect_uri: %s", uri)
		}

		if parsedURI.Fragment != "" {
			return fmt.Errorf("redirect_uri cannot contain fragment: %s", uri)
		}
	}

	return nil
}
