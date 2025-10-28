package bskyoauth

import (
	"crypto/ecdsa"
)

// Session represents an authenticated user session with Bluesky.
type Session struct {
	// DID is the decentralized identifier for the user
	DID string

	// AccessToken is the OAuth access token
	AccessToken string

	// RefreshToken is used to obtain new access tokens
	RefreshToken string

	// DPoPKey is the private key used for DPoP proof generation
	DPoPKey *ecdsa.PrivateKey

	// PDS is the Personal Data Server endpoint for this user
	PDS string

	// DPoPNonce is the server-provided nonce for DPoP proofs
	DPoPNonce string
}

// AuthFlowState contains the state information for an OAuth flow.
type AuthFlowState struct {
	// State is the OAuth state parameter for CSRF protection
	State string

	// CodeVerifier is the PKCE code verifier
	CodeVerifier string

	// DPoPKey is the private key for this authentication flow
	DPoPKey *ecdsa.PrivateKey

	// AuthURL is the authorization URL to redirect the user to
	AuthURL string

	// DID is the user's decentralized identifier
	DID string
}

// SessionStore is an interface for storing and retrieving sessions.
// Implement this interface to provide custom session storage (e.g., Redis, database).
type SessionStore interface {
	// Get retrieves a session by ID
	Get(sessionID string) (*Session, error)

	// Set stores a session with the given ID
	Set(sessionID string, session *Session) error

	// Delete removes a session by ID
	Delete(sessionID string) error
}

// AuthServerMetadata contains OAuth authorization server metadata.
type AuthServerMetadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
}
