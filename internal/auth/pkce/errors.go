package pkce

import "fmt"

// 错误类型
type Error struct {
	Code        string
	Description string
	Details     string
}

func (e *Error) Error() string {
	if e.Details != "" {
		return fmt.Sprintf("PKCE Error [%s]: %s (%s)", e.Code, e.Description, e.Details)
	}
	return fmt.Sprintf("PKCE Error [%s]: %s", e.Code, e.Description)
}

var (
	ErrInvalidVerifierLength  = &Error{Code: "invalid_verifier_length", Description: "code_verifier length must be between 43 and 128 characters"}
	ErrInvalidVerifierCharset = &Error{Code: "invalid_verifier_charset", Description: "code_verifier contains invalid characters"}
	ErrChallengeNotFound      = &Error{Code: "challenge_not_found", Description: "code_challenge not found or expired"}
	ErrChallengeExpired       = &Error{Code: "challenge_expired", Description: "code_challenge has expired"}
	ErrChallengeAlreadyUsed   = &Error{Code: "challenge_already_used", Description: "code_challenge has already been used"}
	ErrVerificationFailed     = &Error{Code: "verification_failed", Description: "code_verifier verification failed"}
	ErrClientMismatch         = &Error{Code: "client_mismatch", Description: "client_id does not match the challenge"}
	ErrTooManyChallenges      = &Error{Code: "too_many_challenges", Description: "maximum number of concurrent challenges exceeded"}
	ErrInvalidChallengeMethod = &Error{Code: "invalid_challenge_method", Description: "unsupported code_challenge_method, only S256 is supported"}
)
