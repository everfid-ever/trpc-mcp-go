package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type PostgresClientStore struct {
	db     *sql.DB
	crypto *CryptoManager
}

func NewPostgresClientStore(db *sql.DB, secretKey string) *PostgresClientStore {
	return &PostgresClientStore{db: db, crypto: NewCryptoManager(secretKey)}
}

// Create stores a new OAuth client
func (s *PostgresClientStore) Create(ctx context.Context, client *OAuthClient) error {
	// Encrypt client secret
	if client.ClientSecret != "" {
		encrypted, err := s.crypto.Encrypt(client.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret: %w", err)
		}
		client.ClientSecret = encrypted
	}

	query := `
		INSERT INTO oauth_clients (
			client_id, client_secret, client_name, redirect_uris, grant_types, 
			response_types, scope, token_endpoint_auth_method, jwks_uri, jwks,
			software_id, software_version, client_uri, logo_uri, tos_uri, 
			policy_uri, contacts, created_at, updated_at, expires_at,
			client_id_issued_at, client_secret_expires_at, application_type,
			subject_type, id_token_signed_response_alg, id_token_encrypted_response_alg,
			id_token_encrypted_response_enc, userinfo_signed_response_alg,
			userinfo_encrypted_response_alg, userinfo_encrypted_response_enc,
			request_object_signing_alg, request_object_encryption_alg,
			request_object_encryption_enc, default_max_age, require_auth_time,
			default_acr_values, initiate_login_uri, request_uris
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
			$16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28,
			$29, $30, $31, $32, $33, $34, $35, $36, $37, $38
		)`

	_, err := s.db.ExecContext(ctx, query,
		client.ClientID, client.ClientSecret, client.ClientName,
		strings.Join(client.RedirectURIs, ","), strings.Join(client.GrantTypes, ","),
		strings.Join(client.ResponseTypes, ","), client.Scope, client.TokenEndpointAuthMethod,
		client.JWKSUri, client.JWKS, client.SoftwareID, client.SoftwareVersion,
		client.ClientURI, client.LogoURI, client.TosURI, client.PolicyURI,
		strings.Join(client.Contacts, ","), client.CreatedAt, client.UpdatedAt,
		client.ExpiresAt, client.ClientIDIssuedAt, client.ClientSecretExpiresAt,
		client.ApplicationType, client.SubjectType, client.IDTokenSignedResponseAlg,
		client.IDTokenEncryptedResponseAlg, client.IDTokenEncryptedResponseEnc,
		client.UserinfoSignedResponseAlg, client.UserinfoEncryptedResponseAlg,
		client.UserinfoEncryptedResponseEnc, client.RequestObjectSigningAlg,
		client.RequestObjectEncryptionAlg, client.RequestObjectEncryptionEnc,
		client.DefaultMaxAge, client.RequireAuthTime,
		strings.Join(client.DefaultACRValues, ","), client.InitiateLoginURI,
		strings.Join(client.RequestURIs, ","),
	)

	if err != nil {
		return fmt.Errorf("failed to create client: %w", err)
	}

	return nil
}

// GetByID retrieves a client by its ID
func (s *PostgresClientStore) GetByID(ctx context.Context, clientID string) (*OAuthClient, error) {
	query := `
		SELECT client_id, client_secret, client_name, redirect_uris, grant_types,
			   response_types, scope, token_endpoint_auth_method, jwks_uri, jwks,
			   software_id, software_version, client_uri, logo_uri, tos_uri,
			   policy_uri, contacts, created_at, updated_at, expires_at,
			   client_id_issued_at, client_secret_expires_at, application_type,
			   subject_type, id_token_signed_response_alg, id_token_encrypted_response_alg,
			   id_token_encrypted_response_enc, userinfo_signed_response_alg,
			   userinfo_encrypted_response_alg, userinfo_encrypted_response_enc,
			   request_object_signing_alg, request_object_encryption_alg,
			   request_object_encryption_enc, default_max_age, require_auth_time,
			   default_acr_values, initiate_login_uri, request_uris
		FROM oauth_clients WHERE client_id = $1`

	var client OAuthClient
	var redirectURIs, grantTypes, responseTypes, contacts, defaultACRValues, requestURIs string

	err := s.db.QueryRowContext(ctx, query, clientID).Scan(
		&client.ClientID, &client.ClientSecret, &client.ClientName,
		&redirectURIs, &grantTypes, &responseTypes, &client.Scope,
		&client.TokenEndpointAuthMethod, &client.JWKSUri, &client.JWKS,
		&client.SoftwareID, &client.SoftwareVersion, &client.ClientURI,
		&client.LogoURI, &client.TosURI, &client.PolicyURI, &contacts,
		&client.CreatedAt, &client.UpdatedAt, &client.ExpiresAt,
		&client.ClientIDIssuedAt, &client.ClientSecretExpiresAt,
		&client.ApplicationType, &client.SubjectType, &client.IDTokenSignedResponseAlg,
		&client.IDTokenEncryptedResponseAlg, &client.IDTokenEncryptedResponseEnc,
		&client.UserinfoSignedResponseAlg, &client.UserinfoEncryptedResponseAlg,
		&client.UserinfoEncryptedResponseEnc, &client.RequestObjectSigningAlg,
		&client.RequestObjectEncryptionAlg, &client.RequestObjectEncryptionEnc,
		&client.DefaultMaxAge, &client.RequireAuthTime, &defaultACRValues,
		&client.InitiateLoginURI, &requestURIs,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("client not found")
		}
		return nil, fmt.Errorf("failed to get client: %w", err)
	}

	// Parse comma-separated fields
	if redirectURIs != "" {
		client.RedirectURIs = strings.Split(redirectURIs, ",")
	}
	if grantTypes != "" {
		client.GrantTypes = strings.Split(grantTypes, ",")
	}
	if responseTypes != "" {
		client.ResponseTypes = strings.Split(responseTypes, ",")
	}
	if contacts != "" {
		client.Contacts = strings.Split(contacts, ",")
	}
	if defaultACRValues != "" {
		client.DefaultACRValues = strings.Split(defaultACRValues, ",")
	}
	if requestURIs != "" {
		client.RequestURIs = strings.Split(requestURIs, ",")
	}

	// Decrypt client secret
	if client.ClientSecret != "" {
		decrypted, err := s.crypto.Decrypt(client.ClientSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt client secret: %w", err)
		}
		client.ClientSecret = decrypted
	}

	return &client, nil
}

// Update updates an existing client
func (s *PostgresClientStore) Update(ctx context.Context, client *OAuthClient) error {
	// Encrypt client secret
	if client.ClientSecret != "" {
		encrypted, err := s.crypto.Encrypt(client.ClientSecret)
		if err != nil {
			return fmt.Errorf("failed to encrypt client secret: %w", err)
		}
		client.ClientSecret = encrypted
	}

	client.UpdatedAt = time.Now()

	query := `
		UPDATE oauth_clients SET
			client_secret = $2, client_name = $3, redirect_uris = $4, grant_types = $5,
			response_types = $6, scope = $7, token_endpoint_auth_method = $8,
			jwks_uri = $9, jwks = $10, software_id = $11, software_version = $12,
			client_uri = $13, logo_uri = $14, tos_uri = $15, policy_uri = $16,
			contacts = $17, updated_at = $18, expires_at = $19,
			client_secret_expires_at = $20, application_type = $21, subject_type = $22,
			id_token_signed_response_alg = $23, id_token_encrypted_response_alg = $24,
			id_token_encrypted_response_enc = $25, userinfo_signed_response_alg = $26,
			userinfo_encrypted_response_alg = $27, userinfo_encrypted_response_enc = $28,
			request_object_signing_alg = $29, request_object_encryption_alg = $30,
			request_object_encryption_enc = $31, default_max_age = $32,
			require_auth_time = $33, default_acr_values = $34,
			initiate_login_uri = $35, request_uris = $36
		WHERE client_id = $1`

	result, err := s.db.ExecContext(ctx, query,
		client.ClientID, client.ClientSecret, client.ClientName,
		strings.Join(client.RedirectURIs, ","), strings.Join(client.GrantTypes, ","),
		strings.Join(client.ResponseTypes, ","), client.Scope, client.TokenEndpointAuthMethod,
		client.JWKSUri, client.JWKS, client.SoftwareID, client.SoftwareVersion,
		client.ClientURI, client.LogoURI, client.TosURI, client.PolicyURI,
		strings.Join(client.Contacts, ","), client.UpdatedAt, client.ExpiresAt,
		client.ClientSecretExpiresAt, client.ApplicationType, client.SubjectType,
		client.IDTokenSignedResponseAlg, client.IDTokenEncryptedResponseAlg,
		client.IDTokenEncryptedResponseEnc, client.UserinfoSignedResponseAlg,
		client.UserinfoEncryptedResponseAlg, client.UserinfoEncryptedResponseEnc,
		client.RequestObjectSigningAlg, client.RequestObjectEncryptionAlg,
		client.RequestObjectEncryptionEnc, client.DefaultMaxAge, client.RequireAuthTime,
		strings.Join(client.DefaultACRValues, ","), client.InitiateLoginURI,
		strings.Join(client.RequestURIs, ","),
	)

	if err != nil {
		return fmt.Errorf("failed to update client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("client not found")
	}

	return nil
}

// Delete removes a client by its ID
func (s *PostgresClientStore) Delete(ctx context.Context, clientID string) error {
	query := `DELETE FROM oauth_clients WHERE client_id = $1`

	result, err := s.db.ExecContext(ctx, query, clientID)
	if err != nil {
		return fmt.Errorf("failed to delete client: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return errors.New("client not found")
	}

	return nil
}

// List returns all clients with pagination
func (s *PostgresClientStore) List(ctx context.Context, offset, limit int) ([]*OAuthClient, int, error) {
	// Get total count
	countQuery := `SELECT COUNT(*) FROM oauth_clients`
	var total int
	err := s.db.QueryRowContext(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get total count: %w", err)
	}

	// Get clients with pagination
	query := `
		SELECT client_id, client_secret, client_name, redirect_uris, grant_types,
			   response_types, scope, token_endpoint_auth_method, jwks_uri, jwks,
			   software_id, software_version, client_uri, logo_uri, tos_uri,
			   policy_uri, contacts, created_at, updated_at, expires_at,
			   client_id_issued_at, client_secret_expires_at, application_type,
			   subject_type, id_token_signed_response_alg, id_token_encrypted_response_alg,
			   id_token_encrypted_response_enc, userinfo_signed_response_alg,
			   userinfo_encrypted_response_alg, userinfo_encrypted_response_enc,
			   request_object_signing_alg, request_object_encryption_alg,
			   request_object_encryption_enc, default_max_age, require_auth_time,
			   default_acr_values, initiate_login_uri, request_uris
		FROM oauth_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	rows, err := s.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query clients: %w", err)
	}
	defer rows.Close()

	clients := make([]*OAuthClient, 0, limit)

	for rows.Next() {
		var client OAuthClient
		var redirectURIs, grantTypes, responseTypes, contacts, defaultACRValues, requestURIs string

		err := rows.Scan(
			&client.ClientID, &client.ClientSecret, &client.ClientName,
			&redirectURIs, &grantTypes, &responseTypes, &client.Scope,
			&client.TokenEndpointAuthMethod, &client.JWKSUri, &client.JWKS,
			&client.SoftwareID, &client.SoftwareVersion, &client.ClientURI,
			&client.LogoURI, &client.TosURI, &client.PolicyURI, &contacts,
			&client.CreatedAt, &client.UpdatedAt, &client.ExpiresAt,
			&client.ClientIDIssuedAt, &client.ClientSecretExpiresAt,
			&client.ApplicationType, &client.SubjectType, &client.IDTokenSignedResponseAlg,
			&client.IDTokenEncryptedResponseAlg, &client.IDTokenEncryptedResponseEnc,
			&client.UserinfoSignedResponseAlg, &client.UserinfoEncryptedResponseAlg,
			&client.UserinfoEncryptedResponseEnc, &client.RequestObjectSigningAlg,
			&client.RequestObjectEncryptionAlg, &client.RequestObjectEncryptionEnc,
			&client.DefaultMaxAge, &client.RequireAuthTime, &defaultACRValues,
			&client.InitiateLoginURI, &requestURIs,
		)

		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan client: %w", err)
		}

		// Parse comma-separated fields
		if redirectURIs != "" {
			client.RedirectURIs = strings.Split(redirectURIs, ",")
		}
		if grantTypes != "" {
			client.GrantTypes = strings.Split(grantTypes, ",")
		}
		if responseTypes != "" {
			client.ResponseTypes = strings.Split(responseTypes, ",")
		}
		if contacts != "" {
			client.Contacts = strings.Split(contacts, ",")
		}
		if defaultACRValues != "" {
			client.DefaultACRValues = strings.Split(defaultACRValues, ",")
		}
		if requestURIs != "" {
			client.RequestURIs = strings.Split(requestURIs, ",")
		}

		// Decrypt client secret
		if client.ClientSecret != "" {
			decrypted, err := s.crypto.Decrypt(client.ClientSecret)
			if err != nil {
				continue // Skip clients with decryption errors
			}
			client.ClientSecret = decrypted
		}

		clients = append(clients, &client)
	}

	return clients, total, nil
}

// GetByCredentials validates client credentials
func (s *PostgresClientStore) GetByCredentials(ctx context.Context, clientID, clientSecret string) (*OAuthClient, error) {
	client, err := s.GetByID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	// Validate client secret
	if client.TokenEndpointAuthMethod != "none" && client.ClientSecret != clientSecret {
		return nil, errors.New("invalid client credentials")
	}

	return client, nil
}

// CleanupExpired removes expired clients
func (s *PostgresClientStore) CleanupExpired(ctx context.Context) (int, error) {
	query := `DELETE FROM oauth_clients WHERE expires_at IS NOT NULL AND expires_at < $1`

	result, err := s.db.ExecContext(ctx, query, time.Now())
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired clients: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

// Close closes the storage connection
func (s *PostgresClientStore) Close() error {
	return s.db.Close()
}
