package store

import (
	"context"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

type ClientRegistrationService struct {
	store     ClientStore
	validator *ClientValidator
}

func NewClientRegistrationService(store ClientStore) *ClientRegistrationService {
	return &ClientRegistrationService{store: store, validator: NewClientValidator()}
}

// generateClientID generates a unique client ID
func (s *ClientRegistrationService) generateClientID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("client_%x", b)
}

// generateClientSecret generates a secure client secret
func (s *ClientRegistrationService) generateClientSecret() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// RegisterClient handles client registration requests
func (s *ClientRegistrationService) RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	// Validate request
	if err := s.validator.ValidateRegistrationRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Set defaults
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}
	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if req.ApplicationType == "" {
		req.ApplicationType = "web"
	}
	if req.SubjectType == "" {
		req.SubjectType = "public"
	}

	// Generate client credentials
	clientID := s.generateClientID()
	var clientSecret string
	if req.TokenEndpointAuthMethod != "none" {
		clientSecret = s.generateClientSecret()
	}

	now := time.Now()

	// Create client
	client := &OAuthClient{
		ClientID:                     clientID,
		ClientSecret:                 clientSecret,
		ClientName:                   req.ClientName,
		RedirectURIs:                 req.RedirectURIs,
		GrantTypes:                   req.GrantTypes,
		ResponseTypes:                req.ResponseTypes,
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		JWKSUri:                      req.JWKSUri,
		JWKS:                         req.JWKS,
		ClientURI:                    req.ClientURI,
		LogoURI:                      req.LogoURI,
		TosURI:                       req.TosURI,
		PolicyURI:                    req.PolicyURI,
		Contacts:                     req.Contacts,
		CreatedAt:                    now,
		UpdatedAt:                    now,
		ClientIDIssuedAt:             now,
		ApplicationType:              req.ApplicationType,
		SubjectType:                  req.SubjectType,
		IDTokenSignedResponseAlg:     req.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoSignedResponseAlg:    req.UserinfoSignedResponseAlg,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
		RequestObjectSigningAlg:      req.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:   req.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:   req.RequestObjectEncryptionEnc,
		DefaultMaxAge:                req.DefaultMaxAge,
		RequireAuthTime:              req.RequireAuthTime,
		DefaultACRValues:             req.DefaultACRValues,
		InitiateLoginURI:             req.InitiateLoginURI,
		RequestURIs:                  req.RequestURIs,
	}

	// Store client
	if err := s.store.Create(ctx, client); err != nil {
		return nil, fmt.Errorf("failed to store client: %w", err)
	}

	// Build response
	response := &ClientRegistrationResponse{
		ClientID:                     clientID,
		ClientIDIssuedAt:             now.Unix(),
		RedirectURIs:                 req.RedirectURIs,
		ResponseTypes:                req.ResponseTypes,
		GrantTypes:                   req.GrantTypes,
		ApplicationType:              req.ApplicationType,
		Contacts:                     req.Contacts,
		ClientName:                   req.ClientName,
		LogoURI:                      req.LogoURI,
		ClientURI:                    req.ClientURI,
		PolicyURI:                    req.PolicyURI,
		TosURI:                       req.TosURI,
		JWKSUri:                      req.JWKSUri,
		JWKS:                         req.JWKS,
		SubjectType:                  req.SubjectType,
		IDTokenSignedResponseAlg:     req.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  req.IDTokenEncryptedResponseEnc,
		UserinfoSignedResponseAlg:    req.UserinfoSignedResponseAlg,
		UserinfoEncryptedResponseAlg: req.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: req.UserinfoEncryptedResponseEnc,
		RequestObjectSigningAlg:      req.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:   req.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:   req.RequestObjectEncryptionEnc,
		TokenEndpointAuthMethod:      req.TokenEndpointAuthMethod,
		DefaultMaxAge:                req.DefaultMaxAge,
		RequireAuthTime:              req.RequireAuthTime,
		DefaultACRValues:             req.DefaultACRValues,
		InitiateLoginURI:             req.InitiateLoginURI,
		RequestURIs:                  req.RequestURIs,
	}

	if clientSecret != "" {
		response.ClientSecret = clientSecret
	}

	return response, nil
}

// GetClient retrieves client information
func (s *ClientRegistrationService) GetClient(ctx context.Context, clientID string) (*ClientRegistrationResponse, error) {
	client, err := s.store.GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	response := &ClientRegistrationResponse{
		ClientID:                     client.ClientID,
		ClientIDIssuedAt:             client.ClientIDIssuedAt.Unix(),
		RedirectURIs:                 client.RedirectURIs,
		ResponseTypes:                client.ResponseTypes,
		GrantTypes:                   client.GrantTypes,
		ApplicationType:              client.ApplicationType,
		Contacts:                     client.Contacts,
		ClientName:                   client.ClientName,
		LogoURI:                      client.LogoURI,
		ClientURI:                    client.ClientURI,
		PolicyURI:                    client.PolicyURI,
		TosURI:                       client.TosURI,
		JWKSUri:                      client.JWKSUri,
		JWKS:                         client.JWKS,
		SubjectType:                  client.SubjectType,
		IDTokenSignedResponseAlg:     client.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:  client.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:  client.IDTokenEncryptedResponseEnc,
		UserinfoSignedResponseAlg:    client.UserinfoSignedResponseAlg,
		UserinfoEncryptedResponseAlg: client.UserinfoEncryptedResponseAlg,
		UserinfoEncryptedResponseEnc: client.UserinfoEncryptedResponseEnc,
		RequestObjectSigningAlg:      client.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:   client.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:   client.RequestObjectEncryptionEnc,
		TokenEndpointAuthMethod:      client.TokenEndpointAuthMethod,
		DefaultMaxAge:                client.DefaultMaxAge,
		RequireAuthTime:              client.RequireAuthTime,
		DefaultACRValues:             client.DefaultACRValues,
		InitiateLoginURI:             client.InitiateLoginURI,
		RequestURIs:                  client.RequestURIs,
	}

	if client.ClientSecret != "" {
		response.ClientSecret = client.ClientSecret
	}

	if client.ClientSecretExpiresAt != nil {
		expiresAt := client.ClientSecretExpiresAt.Unix()
		response.ClientSecretExpiresAt = &expiresAt
	}

	return response, nil
}

// UpdateClient updates client information
func (s *ClientRegistrationService) UpdateClient(ctx context.Context, clientID string, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	// Get existing client
	existingClient, err := s.store.GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Validate request
	if err := s.validator.ValidateRegistrationRequest(req); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	// Update client fields
	existingClient.ClientName = req.ClientName
	existingClient.RedirectURIs = req.RedirectURIs
	existingClient.GrantTypes = req.GrantTypes
	existingClient.ResponseTypes = req.ResponseTypes
	existingClient.JWKSUri = req.JWKSUri
	existingClient.JWKS = req.JWKS
	existingClient.ClientURI = req.ClientURI
	existingClient.LogoURI = req.LogoURI
	existingClient.TosURI = req.TosURI
	existingClient.PolicyURI = req.PolicyURI
	existingClient.Contacts = req.Contacts
	existingClient.ApplicationType = req.ApplicationType
	existingClient.SubjectType = req.SubjectType
	existingClient.IDTokenSignedResponseAlg = req.IDTokenSignedResponseAlg
	existingClient.IDTokenEncryptedResponseAlg = req.IDTokenEncryptedResponseAlg
	existingClient.IDTokenEncryptedResponseEnc = req.IDTokenEncryptedResponseEnc
	existingClient.UserinfoSignedResponseAlg = req.UserinfoSignedResponseAlg
	existingClient.UserinfoEncryptedResponseAlg = req.UserinfoEncryptedResponseAlg
	existingClient.UserinfoEncryptedResponseEnc = req.UserinfoEncryptedResponseEnc
	existingClient.RequestObjectSigningAlg = req.RequestObjectSigningAlg
	existingClient.RequestObjectEncryptionAlg = req.RequestObjectEncryptionAlg
	existingClient.RequestObjectEncryptionEnc = req.RequestObjectEncryptionEnc
	existingClient.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	existingClient.DefaultMaxAge = req.DefaultMaxAge
	existingClient.RequireAuthTime = req.RequireAuthTime
	existingClient.DefaultACRValues = req.DefaultACRValues
	existingClient.InitiateLoginURI = req.InitiateLoginURI
	existingClient.RequestURIs = req.RequestURIs

	// Update in store
	if err := s.store.Update(ctx, existingClient); err != nil {
		return nil, fmt.Errorf("failed to update client: %w", err)
	}

	// Return updated client info
	return s.GetClient(ctx, clientID)
}

// DeleteClient deletes a client
func (s *ClientRegistrationService) DeleteClient(ctx context.Context, clientID string) error {
	return s.store.Delete(ctx, clientID)
}
