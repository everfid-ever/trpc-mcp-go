package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// JWK JSON Web Key结构
type JWK struct {
	KeyType   string `json:"kty"`
	Use       string `json:"use,omitempty"`
	KeyID     string `json:"kid,omitempty"`
	Algorithm string `json:"alg,omitempty"`

	// RSA参数
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC参数
	Curve string `json:"crv,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
}

// JWKSet JSON Web Key Set结构
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// convertJWKToPublicKey converts JWK -> crypto.PublicKey
func (v *TokenVerifier) convertJWKToPublicKey(jwk *JWK) (interface{}, error) {
	switch jwk.KeyType {
	case "RSA", "rsa":
		return v.convertRSAJWK(jwk)
	case "EC", "ec":
		return v.convertECJWK(jwk)
	default:
		return nil, fmt.Errorf("unsupported JWK kty: %s", jwk.KeyType)
	}
}

// convertRSAJWK 转换RSA JWK
func (v *TokenVerifier) convertRSAJWK(jwk *JWK) (*rsa.PublicKey, error) {
	if jwk.N == "" || jwk.E == "" {
		return nil, errors.New("rsa jwk missing n or e")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url for n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url for e: %w", err)
	}
	eInt := 0
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	if eInt == 0 {
		eInt = 65537
	}
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}
	// validate marshalling
	if _, err := x509.MarshalPKIXPublicKey(pub); err != nil {
		return nil, fmt.Errorf("invalid rsa public key: %w", err)
	}
	return pub, nil
}

// convertECJWK 转换EC JWK
func (v *TokenVerifier) convertECJWK(jwk *JWK) (*ecdsa.PublicKey, error) {
	if jwk.X == "" || jwk.Y == "" || jwk.Curve == "" {
		return nil, errors.New("ec jwk missing x/y/curve")
	}
	var curve elliptic.Curve
	switch jwk.Curve {
	case "P-256", "prime256v1", "secp256r1":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Curve)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url for x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url for y: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ec point not on curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
