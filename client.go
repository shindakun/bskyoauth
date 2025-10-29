package bskyoauth

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"

	"github.com/shindakun/bskyoauth/internal/api"
	internalhttp "github.com/shindakun/bskyoauth/internal/http"
)

const (
	// ApplicationTypeWeb indicates a web-based OAuth client.
	// Web clients must use HTTPS redirect URIs (except localhost for development).
	ApplicationTypeWeb = "web"

	// ApplicationTypeNative indicates a native/desktop OAuth client.
	// Native clients may use custom URI schemes or http://localhost redirect URIs.
	ApplicationTypeNative = "native"
)

var (
	// ErrNoSession is returned when no valid session is available
	ErrNoSession = errors.New("no valid session")
)

// Client is the main entry point for the Bluesky OAuth library.
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

// NewClient creates a new Bluesky OAuth client with default settings.
func NewClient(baseURL string) *Client {
	return NewClientWithOptions(ClientOptions{
		BaseURL: baseURL,
	})
}

// NewClientWithOptions creates a new Bluesky OAuth client with custom options.
func NewClientWithOptions(opts ClientOptions) *Client {
	if opts.ClientName == "" {
		opts.ClientName = "Bluesky OAuth Client"
	}

	if len(opts.Scopes) == 0 {
		opts.Scopes = []string{"atproto", "transition:generic"}
	}

	if opts.SessionStore == nil {
		opts.SessionStore = NewMemorySessionStore()
	}

	// Validate and set default ApplicationType
	if opts.ApplicationType == "" {
		opts.ApplicationType = ApplicationTypeWeb
	} else if opts.ApplicationType != ApplicationTypeWeb && opts.ApplicationType != ApplicationTypeNative {
		// Invalid application type - log warning and default to web
		Logger.Warn("invalid application_type, defaulting to 'web'",
			"provided", opts.ApplicationType,
			"valid_values", []string{ApplicationTypeWeb, ApplicationTypeNative})
		opts.ApplicationType = ApplicationTypeWeb
	}

	// Use custom HTTP client if provided
	if opts.HTTPClient != nil {
		SetHTTPClient(opts.HTTPClient)
	}

	// Remove trailing slash from BaseURL to avoid double slashes
	baseURL := opts.BaseURL
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	return &Client{
		BaseURL:         baseURL,
		ClientID:        baseURL + "/client-metadata.json",
		RedirectURI:     baseURL + "/callback",
		ClientName:      opts.ClientName,
		ApplicationType: opts.ApplicationType,
		Scopes:          opts.Scopes,
		SessionStore:    opts.SessionStore,
	}
}

// CreatePost creates a post on Bluesky using the provided session.
func (c *Client) CreatePost(ctx context.Context, session *Session, text string) error {
	if session == nil || session.AccessToken == "" {
		logger := LoggerFromContext(ctx)
		logger.Error("no valid session for CreatePost")
		return ErrNoSession
	}

	// Use internal API client
	apiClient := &api.Client{
		TransportFactory: func(underlying http.RoundTripper, dpopKey *ecdsa.PrivateKey, token string, nonce string) http.RoundTripper {
			return NewDPoPTransport(underlying, dpopKey, token, nonce)
		},
		LoggerGetter: func(ctx context.Context) api.Logger {
			return LoggerFromContext(ctx)
		},
		ValidatePostText: ValidatePostText,
	}

	apiSession := &api.Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
		DPoPKey:     session.DPoPKey,
		DPoPNonce:   session.DPoPNonce,
	}

	err := apiClient.CreatePost(ctx, &api.CreatePostRequest{
		Session: apiSession,
		Text:    text,
	})

	// Update session with the latest nonce
	session.DPoPNonce = apiSession.DPoPNonce

	return err
}

// CreateRecord creates a custom record in the specified collection.
// This is a low-level method that allows creating any type of record.
// The record parameter should be a map[string]interface{} for custom types.
func (c *Client) CreateRecord(ctx context.Context, session *Session, collection string, record map[string]interface{}) (*atproto.RepoCreateRecord_Output, error) {
	if session == nil || session.AccessToken == "" {
		logger := LoggerFromContext(ctx)
		logger.Error("no valid session for CreateRecord")
		return nil, ErrNoSession
	}

	// Use internal API client
	apiClient := &api.Client{
		TransportFactory: func(underlying http.RoundTripper, dpopKey *ecdsa.PrivateKey, token string, nonce string) http.RoundTripper {
			return NewDPoPTransport(underlying, dpopKey, token, nonce)
		},
		LoggerGetter: func(ctx context.Context) api.Logger {
			return LoggerFromContext(ctx)
		},
		ValidateNSID:   ValidateCollectionNSID,
		ValidateRecord: ValidateRecordFields,
	}

	apiSession := &api.Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
		DPoPKey:     session.DPoPKey,
		DPoPNonce:   session.DPoPNonce,
	}

	output, err := apiClient.CreateRecord(ctx, &api.CreateRecordRequest{
		Session:    apiSession,
		Collection: collection,
		Record:     record,
	})

	// Update session with the latest nonce
	session.DPoPNonce = apiSession.DPoPNonce

	return output, err
}

// DeleteRecord deletes a record from the repository.
func (c *Client) DeleteRecord(ctx context.Context, session *Session, collection, rkey string) error {
	if session == nil || session.AccessToken == "" {
		logger := LoggerFromContext(ctx)
		logger.Error("no valid session for DeleteRecord")
		return ErrNoSession
	}

	// Use internal API client
	apiClient := &api.Client{
		TransportFactory: func(underlying http.RoundTripper, dpopKey *ecdsa.PrivateKey, token string, nonce string) http.RoundTripper {
			return NewDPoPTransport(underlying, dpopKey, token, nonce)
		},
		LoggerGetter: func(ctx context.Context) api.Logger {
			return LoggerFromContext(ctx)
		},
	}

	apiSession := &api.Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
		DPoPKey:     session.DPoPKey,
		DPoPNonce:   session.DPoPNonce,
	}

	err := apiClient.DeleteRecord(ctx, &api.DeleteRecordRequest{
		Session:    apiSession,
		Collection: collection,
		Rkey:       rkey,
	})

	// Update session with the latest nonce
	session.DPoPNonce = apiSession.DPoPNonce

	return err
}

// GetClientMetadata returns the OAuth client metadata as a JSON-serializable map.
func (c *Client) GetClientMetadata() map[string]interface{} {
	return map[string]interface{}{
		"client_id":                  c.ClientID,
		"client_name":                c.ClientName,
		"redirect_uris":              []string{c.RedirectURI},
		"scope":                      "atproto transition:generic",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
		"application_type":           c.ApplicationType,
		"dpop_bound_access_tokens":   true,
	}
}

// ClientMetadataHandler returns an HTTP handler that serves the OAuth client metadata.
func (c *Client) ClientMetadataHandler() http.HandlerFunc {
	handlers := &internalhttp.Handlers{
		GetClientMetadata: c.GetClientMetadata,
	}
	return handlers.ClientMetadata()
}

// LoginHandler returns an HTTP handler that initiates the OAuth flow.
// Query parameter: handle (required) - the user's Bluesky handle
func (c *Client) LoginHandler() http.HandlerFunc {
	authFlowAdapter := &authFlowAdapter{client: c}

	handlers := &internalhttp.Handlers{
		AuthFlow: authFlowAdapter,
		LoggerGetter: func(ctx context.Context) internalhttp.Logger {
			return LoggerFromContext(ctx)
		},
		ValidateHandle: ValidateHandle,
	}
	return handlers.Login()
}

// CallbackHandler returns an HTTP handler that completes the OAuth flow.
// Query parameters: code, state, iss (all required)
// On success, creates a session and calls the success handler with the session ID.
func (c *Client) CallbackHandler(onSuccess func(w http.ResponseWriter, r *http.Request, sessionID string)) http.HandlerFunc {
	// Create adapters to convert between internal and public types
	authFlowAdapter := &authFlowAdapter{client: c}
	sessionStoreAdapter := &sessionStoreAdapter{store: c.SessionStore}

	handlers := &internalhttp.Handlers{
		AuthFlow:     authFlowAdapter,
		SessionStore: sessionStoreAdapter,
		LoggerGetter: func(ctx context.Context) internalhttp.Logger {
			return LoggerFromContext(ctx)
		},
		GenerateSessionID: GenerateSessionID,
	}
	return handlers.Callback(onSuccess)
}

// authFlowAdapter adapts Client to internalhttp.AuthFlow interface
type authFlowAdapter struct {
	client *Client
}

func (a *authFlowAdapter) StartAuthFlow(ctx context.Context, handle string) (*internalhttp.FlowState, error) {
	state, err := a.client.StartAuthFlow(ctx, handle)
	if err != nil {
		return nil, err
	}
	return &internalhttp.FlowState{AuthURL: state.AuthURL}, nil
}

func (a *authFlowAdapter) CompleteAuthFlow(ctx context.Context, code, state, iss string) (*internalhttp.Session, error) {
	session, err := a.client.CompleteAuthFlow(ctx, code, state, iss)
	if err != nil {
		return nil, err
	}
	return &internalhttp.Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
	}, nil
}

// sessionStoreAdapter adapts SessionStore to internal interface
type sessionStoreAdapter struct {
	store SessionStore
}

func (s *sessionStoreAdapter) Set(sessionID string, session *internalhttp.Session) error {
	// We only need to store what internal/http knows about
	// The real Session object is managed by the Client
	// For now, just delegate - the Session types are compatible for storage
	publicSession := &Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
	}
	return s.store.Set(sessionID, publicSession)
}

// GetSession retrieves a session by ID from the session store.
func (c *Client) GetSession(sessionID string) (*Session, error) {
	return c.SessionStore.Get(sessionID)
}

// DeleteSession removes a session by ID from the session store.
func (c *Client) DeleteSession(sessionID string) error {
	return c.SessionStore.Delete(sessionID)
}

// UpdateSession updates an existing session with new tokens after refresh.
// This is typically used after calling RefreshToken to persist the new tokens.
func (c *Client) UpdateSession(sessionID string, newSession *Session) error {
	return c.SessionStore.Set(sessionID, newSession)
}

// IsAccessTokenExpired checks if the access token has expired or will expire soon.
// The buffer parameter adds a safety margin (e.g., 5 minutes) to refresh before actual expiration.
// Returns false if no expiration info is available (assumes valid).
func (s *Session) IsAccessTokenExpired(buffer time.Duration) bool {
	if s.AccessTokenExpiresAt.IsZero() {
		return false // No expiration info, assume valid
	}
	return time.Now().Add(buffer).After(s.AccessTokenExpiresAt)
}

// IsRefreshTokenExpired checks if the refresh token has expired.
// Returns false if no expiration info is available (assumes valid).
func (s *Session) IsRefreshTokenExpired() bool {
	if s.RefreshTokenExpiresAt.IsZero() {
		return false // No expiration info, assume valid
	}
	return time.Now().After(s.RefreshTokenExpiresAt)
}

// TimeUntilAccessTokenExpiry returns duration until access token expires.
// Returns 0 if already expired or no expiration info available.
func (s *Session) TimeUntilAccessTokenExpiry() time.Duration {
	if s.AccessTokenExpiresAt.IsZero() {
		return 0
	}
	remaining := time.Until(s.AccessTokenExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}
