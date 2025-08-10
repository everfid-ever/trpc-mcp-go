package store

import "context"

type ClientStore interface {
	Create(ctx context.Context, client *OAuthClient) error

	GetByID(ctx context.Context, clientID string) (*OAuthClient, error)

	Update(ctx context.Context, client *OAuthClient) error

	Delete(ctx context.Context, clientID string) error

	List(ctx context.Context, offset, limit int) ([]*OAuthClient, int, error)

	GetByCredentials(ctx context.Context, clientID, clientSecret string) (*OAuthClient, error)

	CleanupExpired(ctx context.Context) (int, error)

	Close() error
}
