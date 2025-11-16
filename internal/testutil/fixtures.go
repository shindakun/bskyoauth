package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

// NewTestDPoPKey generates a test ECDSA P-256 key for DPoP.
// If generation fails, the test is failed with t.Fatal.
func NewTestDPoPKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate DPoP key: %v", err)
	}
	return key
}

// TestSession represents a test session with all fields populated.
type TestSession struct {
	DID                   string
	AccessToken           string
	RefreshToken          string
	DPoPKey               *ecdsa.PrivateKey
	PDS                   string
	DPoPNonce             string
	Handle                string
	Email                 string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
}

// NewTestSession creates a test session with sensible defaults.
// Pass options to customize the session.
func NewTestSession(t *testing.T, opts ...TestSessionOption) *TestSession {
	t.Helper()

	// Default values
	session := &TestSession{
		DID:                   "did:plc:test123abc",
		AccessToken:           "test-access-token-" + RandomString(16),
		RefreshToken:          "test-refresh-token-" + RandomString(16),
		DPoPKey:               NewTestDPoPKey(t),
		PDS:                   "https://test.pds.example.com",
		DPoPNonce:             "test-nonce-" + RandomString(8),
		Handle:                "testuser.test",
		Email:                 "test@example.com",
		AccessTokenExpiresAt:  time.Now().Add(12 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}

	// Apply options
	for _, opt := range opts {
		opt(session)
	}

	return session
}

// TestSessionOption is a function that modifies a TestSession.
type TestSessionOption func(*TestSession)

// WithDID sets the DID for the test session.
func WithDID(did string) TestSessionOption {
	return func(s *TestSession) {
		s.DID = did
	}
}

// WithAccessToken sets the access token for the test session.
func WithAccessToken(token string) TestSessionOption {
	return func(s *TestSession) {
		s.AccessToken = token
	}
}

// WithRefreshToken sets the refresh token for the test session.
func WithRefreshToken(token string) TestSessionOption {
	return func(s *TestSession) {
		s.RefreshToken = token
	}
}

// WithPDS sets the PDS URL for the test session.
func WithPDS(pds string) TestSessionOption {
	return func(s *TestSession) {
		s.PDS = pds
	}
}

// WithDPoPNonce sets the DPoP nonce for the test session.
func WithDPoPNonce(nonce string) TestSessionOption {
	return func(s *TestSession) {
		s.DPoPNonce = nonce
	}
}

// WithHandle sets the handle for the test session.
func WithHandle(handle string) TestSessionOption {
	return func(s *TestSession) {
		s.Handle = handle
	}
}

// WithExpiredAccessToken sets the access token to be expired.
func WithExpiredAccessToken() TestSessionOption {
	return func(s *TestSession) {
		s.AccessTokenExpiresAt = time.Now().Add(-1 * time.Hour)
	}
}

// WithExpiredRefreshToken sets the refresh token to be expired.
func WithExpiredRefreshToken() TestSessionOption {
	return func(s *TestSession) {
		s.RefreshTokenExpiresAt = time.Now().Add(-1 * time.Hour)
	}
}

// TestAuthServerMetadata represents OAuth server metadata for testing.
type TestAuthServerMetadata struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
}

// NewTestAuthServerMetadata creates test OAuth server metadata.
// Pass a base URL to customize the endpoints.
func NewTestAuthServerMetadata(baseURL string) *TestAuthServerMetadata {
	if baseURL == "" {
		baseURL = "https://test.oauth.example.com"
	}

	return &TestAuthServerMetadata{
		Issuer:                baseURL,
		AuthorizationEndpoint: baseURL + "/authorize",
		TokenEndpoint:         baseURL + "/token",
		JWKSURI:               baseURL + "/.well-known/jwks.json",
	}
}

// TestClientConfig represents test client configuration.
type TestClientConfig struct {
	BaseURL         string
	ClientID        string
	RedirectURI     string
	ClientName      string
	ApplicationType string
	Scopes          []string
}

// NewTestClientConfig creates test client configuration.
func NewTestClientConfig() *TestClientConfig {
	baseURL := "http://localhost:8181"
	return &TestClientConfig{
		BaseURL:         baseURL,
		ClientID:        baseURL + "/oauth-client-metadata.json",
		RedirectURI:     baseURL + "/callback",
		ClientName:      "Test OAuth Client",
		ApplicationType: "web",
		Scopes:          []string{"atproto", "transition:generic"},
	}
}

// RandomString generates a random string of the specified length.
// Uses URL-safe base64 characters.
func RandomString(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}
