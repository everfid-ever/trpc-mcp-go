package store

const PostgreSQLSchema = `
-- OAuth clients table
CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id VARCHAR(255) PRIMARY KEY,
    client_secret TEXT,
    client_name VARCHAR(255),
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    response_types TEXT NOT NULL,
    scope TEXT,
    token_endpoint_auth_method VARCHAR(50) NOT NULL DEFAULT 'client_secret_basic',
    jwks_uri TEXT,
    jwks TEXT,
    software_id VARCHAR(255),
    software_version VARCHAR(255),
    client_uri TEXT,
    logo_uri TEXT,
    tos_uri TEXT,
    policy_uri TEXT,
    contacts TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE,
    client_id_issued_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    client_secret_expires_at TIMESTAMP WITH TIME ZONE,
    application_type VARCHAR(50) DEFAULT 'web',
    subject_type VARCHAR(50) DEFAULT 'public',
    id_token_signed_response_alg VARCHAR(50),
    id_token_encrypted_response_alg VARCHAR(50),
    id_token_encrypted_response_enc VARCHAR(50),
    userinfo_signed_response_alg VARCHAR(50),
    userinfo_encrypted_response_alg VARCHAR(50),
    userinfo_encrypted_response_enc VARCHAR(50),
    request_object_signing_alg VARCHAR(50),
    request_object_encryption_alg VARCHAR(50),
    request_object_encryption_enc VARCHAR(50),
    default_max_age INTEGER DEFAULT 0,
    require_auth_time BOOLEAN DEFAULT FALSE,
    default_acr_values TEXT,
    initiate_login_uri TEXT,
    request_uris TEXT
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_oauth_clients_created_at ON oauth_clients(created_at);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_expires_at ON oauth_clients(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_oauth_clients_application_type ON oauth_clients(application_type);

-- Trigger to automatically update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$ language 'plpgsql';

CREATE TRIGGER update_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
`
