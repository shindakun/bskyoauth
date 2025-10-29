package bskyoauth

import (
	"crypto/ecdsa"
	"net/http"
	"time"
)

// Client is the main entry point for the Bluesky OAuth library.
// It manages OAuth flows, session storage, and API interactions.
type Client struct {
	// BaseURL is the base URL of the OAuth client (e.g., "http://localhost:8181")
	BaseURL string

	// ClientID is the OAuth client identifier (typically BaseURL + "/client-metadata.json")
	ClientID string

	// RedirectURI is where the OAuth provider redirects after authorization
	RedirectURI string

	// ClientName is the display name for the OAuth client
	ClientName string

	// ApplicationType is the type of OAuth client ("web" or "native")
	ApplicationType string

	// Scopes are the OAuth scopes to request (defaults to "atproto transition:generic")
	Scopes []string

	// SessionStore is the storage backend for sessions
	SessionStore SessionStore
}

// ClientOptions contains configuration options for creating a new Client.
type ClientOptions struct {
	// BaseURL is the base URL of the OAuth client (required)
	BaseURL string

	// ClientName is the display name for the OAuth client (optional, defaults to "Bluesky OAuth Client")
	ClientName string

	// ApplicationType is the type of OAuth client (optional, defaults to "web")
	// Valid values: ApplicationTypeWeb ("web") or ApplicationTypeNative ("native")
	ApplicationType string

	// Scopes are the OAuth scopes to request (optional, defaults to ["atproto", "transition:generic"])
	Scopes []string

	// SessionStore is the storage backend for sessions (optional, defaults to in-memory store)
	SessionStore SessionStore

	// HTTPClient is a custom HTTP client to use for all requests (optional, defaults to client with 30s timeout)
	// Use this to customize timeouts, transport settings, or proxy configuration
	HTTPClient *http.Client
}

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

	// AccessTokenExpiresAt is when the access token expires
	AccessTokenExpiresAt time.Time

	// RefreshTokenExpiresAt is when the refresh token expires (optional, may be zero)
	RefreshTokenExpiresAt time.Time
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
