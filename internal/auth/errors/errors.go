package errors

import "fmt"

// AuthError 表示 OAuth 2.1 规范错误
type AuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
}

func (e *AuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// 通用 OAuth 2.1 错误
var (
	ErrInvalidRequest = &AuthError{
		Code:        "invalid_request",
		Description: "The request is missing a required parameter or is malformed",
		HTTPStatus:  400,
	}
	ErrInvalidClient = &AuthError{
		Code:        "invalid_client",
		Description: "Client authentication failed",
		HTTPStatus:  401,
	}
	ErrInvalidToken = &AuthError{
		Code:        "invalid_token",
		Description: "The access token provided is invalid",
		HTTPStatus:  401,
	}
	ErrExpiredToken = &AuthError{
		Code:        "expired_token",
		Description: "The access token has expired",
		HTTPStatus:  401,
	}
	ErrInsufficientScope = &AuthError{
		Code:        "insufficient_scope",
		Description: "The request requires higher privileges",
		HTTPStatus:  403,
	}
	ErrInvalidGrant = &AuthError{
		Code:        "invalid_grant",
		Description: "The authorization grant is invalid, expired, or revoked",
		HTTPStatus:  400,
	}
	ErrUnsupportedGrantType = &AuthError{
		Code:        "unsupported_grant_type",
		Description: "The authorization grant type is not supported by the server",
		HTTPStatus:  400,
	}
	ErrServerError = &AuthError{
		Code:        "server_error",
		Description: "The authorization server encountered an unexpected condition",
		HTTPStatus:  500,
	}
	ErrCodeUsed = &AuthError{
		Code:        "invalid_grant",
		Description: "Authorization code has already been used",
		HTTPStatus:  400,
	}
	ErrCodeExpired = &AuthError{
		Code:        "invalid_grant",
		Description: "Authorization code has expired",
		HTTPStatus:  400,
	}
)
