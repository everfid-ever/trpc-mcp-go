package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

const pkceCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"

var codeVerifierRegex = regexp.MustCompile(`^[A-Za-z0-9\-\._~]{43,128}$`)

// 生成符合规范的 code_verifier
func GenerateSecureVerifier(length int) (string, error) {
	if length < 43 || length > 128 {
		return "", ErrInvalidVerifierLength
	}
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", &Error{
			Code:        "random_generation_failed",
			Description: "failed to generate cryptographically secure random data",
			Details:     err.Error(),
		}
	}
	verifier := make([]byte, length)
	charsetLen := len(pkceCharset)
	for i := 0; i < length; i++ {
		verifier[i] = pkceCharset[int(randomBytes[i])%charsetLen]
	}
	return string(verifier), nil
}

// 计算 S256 challenge
func ComputeS256Challenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// 常量时间比较
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// 校验 code_verifier
func ValidateVerifier(verifier string) error {
	if len(verifier) < 43 || len(verifier) > 128 {
		return ErrInvalidVerifierLength
	}
	if !codeVerifierRegex.MatchString(verifier) {
		return ErrInvalidVerifierCharset
	}
	return nil
}

// 验证方法
func ValidateS256Method(method string) error {
	if method != "S256" {
		return ErrInvalidChallengeMethod
	}
	return nil
}

// 验证 S256 challenge
func VerifyS256Challenge(verifier, challenge string) bool {
	return ConstantTimeEqual(ComputeS256Challenge(verifier), challenge)
}

// 快速创建一对 verifier+challenge
func CreatePKCEPair(length int) (verifier, challenge string, err error) {
	verifier, err = GenerateSecureVerifier(length)
	if err != nil {
		return "", "", err
	}
	challenge = ComputeS256Challenge(verifier)
	return verifier, challenge, nil
}
