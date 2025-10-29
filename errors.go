package bskyoauth

import (
	"context"
	"errors"
	"net"
	"os"

	"github.com/shindakun/bskyoauth/internal/jwt"
	"github.com/shindakun/bskyoauth/internal/session"
	"github.com/shindakun/bskyoauth/internal/validation"
)

// Client Errors
var (
	// ErrNoSession is returned when no valid session is available
	ErrNoSession = errors.New("no valid session")
)

// OAuth Errors
var (
	// ErrInvalidHandle is returned when the handle cannot be parsed or resolved
	ErrInvalidHandle = errors.New("invalid handle")

	// ErrInvalidState is returned when the OAuth state parameter is invalid
	ErrInvalidState = errors.New("invalid state parameter")

	// ErrTokenExchange is returned when token exchange fails
	ErrTokenExchange = errors.New("token exchange failed")

	// ErrNoAccessToken is returned when no access token is received
	ErrNoAccessToken = errors.New("no access token in response")

	// ErrTokenRefreshFailed is returned when token refresh fails
	ErrTokenRefreshFailed = errors.New("token refresh failed")

	// ErrIssuerMismatch is returned when the issuer doesn't match expected value
	ErrIssuerMismatch = errors.New("issuer mismatch")

	// ErrMetadataFetch is returned when OAuth server metadata cannot be fetched
	ErrMetadataFetch = errors.New("failed to fetch OAuth server metadata")
)

// JWT Errors
// Re-exported from internal/jwt for backward compatibility
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

// Session Errors
// Re-exported from internal/session for backward compatibility
var (
	// ErrSessionNotFound is returned when a session ID doesn't exist
	ErrSessionNotFound = session.ErrSessionNotFound

	// ErrInvalidSession is returned when a session is invalid or expired
	ErrInvalidSession = session.ErrInvalidSession
)

// Validation Errors
// Re-exported from internal/validation for backward compatibility
var (
	// ErrHandleInvalid is returned when handle format is invalid
	ErrHandleInvalid = validation.ErrHandleInvalid

	// ErrHandleTooLong is returned when handle exceeds maximum length
	ErrHandleTooLong = validation.ErrHandleTooLong

	// ErrTextEmpty is returned when text cannot be empty
	ErrTextEmpty = validation.ErrTextEmpty

	// ErrTextTooLong is returned when text exceeds maximum length
	ErrTextTooLong = validation.ErrTextTooLong

	// ErrInvalidUTF8 is returned when text contains invalid UTF-8
	ErrInvalidUTF8 = validation.ErrInvalidUTF8

	// ErrNullByte is returned when text contains null bytes
	ErrNullByte = validation.ErrNullByte

	// ErrRecordFieldInvalid is returned when record field is invalid
	ErrRecordFieldInvalid = validation.ErrRecordFieldInvalid

	// ErrInvalidDatetime is returned when datetime format is invalid
	ErrInvalidDatetime = validation.ErrInvalidDatetime

	// ErrInvalidCollection is returned when collection NSID is invalid
	ErrInvalidCollection = validation.ErrInvalidCollection
)

// IsTimeoutError checks if an error is a timeout error.
// Returns true for context deadline exceeded, network timeouts, and OS deadline exceeded.
func IsTimeoutError(err error) bool {
	if err == nil {
		return false
	}

	// Check for context deadline exceeded
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	// Check for net.Error timeout
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	// Check for os.ErrDeadlineExceeded
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}

	return false
}
