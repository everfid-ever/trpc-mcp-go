package errors

import (
	"errors"
)

type OAuthError error

// OAuthErrorResponse OAuth 2.1草案标准错误响应。
type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

var (
	// OAuth Errors
	ErrInvalidRequest          OAuthError = errors.New("invalid request")
	ErrInvalidClient           OAuthError = errors.New("invalid client")
	ErrInvalidGrant            OAuthError = errors.New("invalid grant")
	ErrUnauthorizedClient      OAuthError = errors.New("unauthorized client")
	ErrUnsupportedGrantType    OAuthError = errors.New("unsupported grant type")
	ErrInvalidScope            OAuthError = errors.New("invalid scope")
	ErrAccessDenied            OAuthError = errors.New("access denied")
	ErrServerError             OAuthError = errors.New("server error")
	ErrTemporarilyUnavailable  OAuthError = errors.New("temporarily unavailable")
	ErrUnsupportedResponseType OAuthError = errors.New("unsupported response type")
	ErrUnsupportedTokenType    OAuthError = errors.New("unsupported token type")
	ErrInvalidToken            OAuthError = errors.New("invalid token")
	ErrMethodNotAllowed        OAuthError = errors.New("method not allowed")
	ErrTooManyRequests         OAuthError = errors.New("too many requests")
	ErrInvalidClientMetadata   OAuthError = errors.New("invalid client metadata")
	ErrInsufficientScope       OAuthError = errors.New("insufficient scope")
	ErrRegistrationUnsupported OAuthError = errors.New("dynamic client registration is unsupported")
	ErrRevokeTokenFailed       OAuthError = errors.New("revoke token failed")
)

// NewOAuthErrorResponse creates a new OAuthErrorResponse
func NewOAuthErrorResponse(errCode OAuthError, message string, uri string) OAuthErrorResponse {
	resp := OAuthErrorResponse{
		Error: errCode.Error(),
	}
	if uri != "" {
		resp.ErrorURI = uri
	}
	if message != "" {
		resp.ErrorDescription = message
	}
	return resp
}
