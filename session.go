package bskyoauth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

var (
	// ErrSessionNotFound is returned when a session ID doesn't exist
	ErrSessionNotFound = errors.New("session not found")

	// ErrInvalidSession is returned when a session is invalid or expired
	ErrInvalidSession = errors.New("invalid session")
)

// GenerateSessionID creates a cryptographically secure random session ID.
func GenerateSessionID() string {
	return generateSecureRandomString(32)
}

// generateSecureRandomString generates a cryptographically secure random string.
func generateSecureRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}
