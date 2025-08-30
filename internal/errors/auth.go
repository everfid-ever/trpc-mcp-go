package errors

import (
	"errors"
)

type OAuthErrorCode error

// OAuthError OAuth 2.1草案标准错误响应。
type OAuthError struct {
	ErrorCode string
	Message   string
	ErrorURI  string
}

type OAuthErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

var (
	// OAuth Errors
	ErrInvalidRequest          OAuthErrorCode = errors.New("invalid request")
	ErrInvalidClient           OAuthErrorCode = errors.New("invalid client")
	ErrInvalidGrant            OAuthErrorCode = errors.New("invalid grant")
	ErrUnauthorizedClient      OAuthErrorCode = errors.New("unauthorized client")
	ErrUnsupportedGrantType    OAuthErrorCode = errors.New("unsupported grant type")
	ErrInvalidScope            OAuthErrorCode = errors.New("invalid scope")
	ErrAccessDenied            OAuthErrorCode = errors.New("access denied")
	ErrServerError             OAuthErrorCode = errors.New("server error")
	ErrTemporarilyUnavailable  OAuthErrorCode = errors.New("temporarily unavailable")
	ErrUnsupportedResponseType OAuthErrorCode = errors.New("unsupported response type")
	ErrUnsupportedTokenType    OAuthErrorCode = errors.New("unsupported token type")
	ErrInvalidToken            OAuthErrorCode = errors.New("invalid token")
	ErrMethodNotAllowed        OAuthErrorCode = errors.New("method not allowed")
	ErrTooManyRequests         OAuthErrorCode = errors.New("too many requests")
	ErrInvalidClientMetadata   OAuthErrorCode = errors.New("invalid client metadata")
	ErrInsufficientScope       OAuthErrorCode = errors.New("insufficient scope")
)

// OAuthErrors maps error codes to their corresponding OAuthErrorCode constants
// Similar to TypeScript's OAUTH_ERRORS mapping for cleaner error handling
var OAuthErrors = map[string]OAuthErrorCode{
	"invalid_request":          ErrInvalidRequest,
	"invalid_client":           ErrInvalidClient,
	"invalid_grant":            ErrInvalidGrant,
	"unauthorized_client":      ErrUnauthorizedClient,
	"unsupported_grant_type":   ErrUnsupportedGrantType,
	"invalid_scope":            ErrInvalidScope,
	"access_denied":            ErrAccessDenied,
	"server_error":             ErrServerError,
	"temporarily_unavailable":  ErrTemporarilyUnavailable,
	"unsupported_response_type": ErrUnsupportedResponseType,
	"unsupported_token_type":   ErrUnsupportedTokenType,
	"invalid_token":            ErrInvalidToken,
	"method_not_allowed":       ErrMethodNotAllowed,
	"too_many_requests":        ErrTooManyRequests,
	"invalid_client_metadata":  ErrInvalidClientMetadata,
	"insufficient_scope":       ErrInsufficientScope,
}

// NewOAuthError creates a new OAuthError
func NewOAuthError(errCode OAuthErrorCode, message string, uri string) OAuthError {
	err := OAuthError{
		ErrorCode: errCode.Error(),
	}
	if uri != "" {
		err.ErrorURI = uri
	}
	if message != "" {
		err.Message = message
	}
	return err
}

func (o OAuthError) ToResponseStruct() *OAuthErrorResponse {
	return &OAuthErrorResponse{
		Error:            o.ErrorCode,
		ErrorDescription: o.Message,
		ErrorURI:         o.ErrorURI,
	}
}

func (o OAuthError) Error() string {
	return o.ErrorCode
}
