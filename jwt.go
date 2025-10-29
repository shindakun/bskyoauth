package bskyoauth

import (
	"github.com/shindakun/bskyoauth/internal/jwt"
)

// Re-export JWT-related errors for backward compatibility
var (
	// ErrInvalidToken indicates the access token is invalid.
	ErrInvalidToken = jwt.ErrInvalidToken

	// ErrTokenExpired indicates the access token has expired.
	ErrTokenExpired = jwt.ErrTokenExpired

	// ErrInvalidSignature indicates the token signature is invalid.
	ErrInvalidSignature = jwt.ErrInvalidSignature

	// ErrInvalidIssuer indicates the token issuer doesn't match expected value.
	ErrInvalidIssuer = jwt.ErrInvalidIssuer

	// ErrJWKSFetch indicates failure to fetch JWKS from the authorization server.
	ErrJWKSFetch = jwt.ErrJWKSFetch

	// ErrInvalidAlgorithm indicates the token uses an unsupported algorithm.
	ErrInvalidAlgorithm = jwt.ErrInvalidAlgorithm

	// ErrMissingClaims indicates required claims are missing from the token.
	ErrMissingClaims = jwt.ErrMissingClaims
)
