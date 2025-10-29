package testutil

import (
	"testing"
)

// TestNewTestDPoPKey verifies that DPoP key generation works.
func TestNewTestDPoPKey(t *testing.T) {
	key := NewTestDPoPKey(t)
	AssertNotNil(t, key, "DPoP key should not be nil")
	AssertNotNil(t, key.PublicKey, "Public key should not be nil")
}

// TestNewTestSession verifies that test session creation works.
func TestNewTestSession(t *testing.T) {
	session := NewTestSession(t)

	AssertNotEqual(t, session.DID, "", "DID should not be empty")
	AssertNotEqual(t, session.AccessToken, "", "AccessToken should not be empty")
	AssertNotEqual(t, session.RefreshToken, "", "RefreshToken should not be empty")
	AssertNotNil(t, session.DPoPKey, "DPoPKey should not be nil")
	AssertNotEqual(t, session.PDS, "", "PDS should not be empty")
	AssertNotEqual(t, session.DPoPNonce, "", "DPoPNonce should not be empty")
}

// TestNewTestSessionWithOptions verifies that test session options work.
func TestNewTestSessionWithOptions(t *testing.T) {
	customDID := "did:plc:custom123"
	customPDS := "https://custom.pds.com"

	session := NewTestSession(t,
		WithDID(customDID),
		WithPDS(customPDS),
	)

	AssertEqual(t, session.DID, customDID, "DID should match custom value")
	AssertEqual(t, session.PDS, customPDS, "PDS should match custom value")
}

// TestNewTestSessionExpired verifies expired token options.
func TestNewTestSessionExpired(t *testing.T) {
	session := NewTestSession(t,
		WithExpiredAccessToken(),
		WithExpiredRefreshToken(),
	)

	AssertTrue(t, session.AccessTokenExpiresAt.Before(session.RefreshTokenExpiresAt), "Access token should be in the past")
}

// TestNewTestAuthServerMetadata verifies metadata creation.
func TestNewTestAuthServerMetadata(t *testing.T) {
	metadata := NewTestAuthServerMetadata("")

	AssertNotEqual(t, metadata.Issuer, "", "Issuer should not be empty")
	AssertNotEqual(t, metadata.AuthorizationEndpoint, "", "AuthorizationEndpoint should not be empty")
	AssertNotEqual(t, metadata.TokenEndpoint, "", "TokenEndpoint should not be empty")
	AssertNotEqual(t, metadata.JWKSURI, "", "JWKSURI should not be empty")
}

// TestNewTestClientConfig verifies client config creation.
func TestNewTestClientConfig(t *testing.T) {
	config := NewTestClientConfig()

	AssertNotEqual(t, config.BaseURL, "", "BaseURL should not be empty")
	AssertNotEqual(t, config.ClientID, "", "ClientID should not be empty")
	AssertNotEqual(t, config.RedirectURI, "", "RedirectURI should not be empty")
	AssertTrue(t, len(config.Scopes) > 0, "Scopes should not be empty")
}

// TestRandomString verifies random string generation.
func TestRandomString(t *testing.T) {
	length := 16
	str := RandomString(length)

	AssertEqual(t, len(str), length, "Random string should have correct length")

	// Verify uniqueness
	str2 := RandomString(length)
	AssertNotEqual(t, str, str2, "Random strings should be unique")
}
