package bskyoauth

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"

	"github.com/shindakun/bskyoauth/internal/api"
	internalhttp "github.com/shindakun/bskyoauth/internal/http"
	_ "github.com/shindakun/bskyoauth/lexicon" // Register custom lexicons
)

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
		ClientID:        baseURL + "/oauth-client-metadata.json",
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

	// Audit: Post creation
	if err != nil {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventPostCreate,
			Actor:     session.DID,
			Action:    "create_post",
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
	} else {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventPostCreate,
			Actor:     session.DID,
			Action:    "create_post",
			Result:    AuditResultSuccess,
		})
	}

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

	// Audit: Record creation
	if err != nil {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordCreate,
			Actor:     session.DID,
			Action:    "create_record",
			Resource:  collection,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
	} else {
		var resourceURI string
		if output != nil {
			resourceURI = output.Uri
		}
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordCreate,
			Actor:     session.DID,
			Action:    "create_record",
			Resource:  resourceURI,
			Result:    AuditResultSuccess,
			Metadata: map[string]interface{}{
				"collection": collection,
			},
		})
	}

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

	// Audit: Record deletion
	resourceURI := "at://" + session.DID + "/" + collection + "/" + rkey
	if err != nil {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordDelete,
			Actor:     session.DID,
			Action:    "delete_record",
			Resource:  resourceURI,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
	} else {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordDelete,
			Actor:     session.DID,
			Action:    "delete_record",
			Resource:  resourceURI,
			Result:    AuditResultSuccess,
		})
	}

	return err
}

// GetRecord retrieves a record from the specified collection.
// This is a low-level method that allows fetching any type of record.
// Returns the record as a map[string]interface{} for flexibility.
func (c *Client) GetRecord(ctx context.Context, session *Session, collection, rkey string) (map[string]interface{}, error) {
	if session == nil || session.AccessToken == "" {
		logger := LoggerFromContext(ctx)
		logger.Error("no valid session for GetRecord")
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
		ValidateNSID: ValidateCollectionNSID,
	}

	apiSession := &api.Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
		DPoPKey:     session.DPoPKey,
		DPoPNonce:   session.DPoPNonce,
	}

	record, err := apiClient.GetRecord(ctx, &api.GetRecordRequest{
		Session:    apiSession,
		Collection: collection,
		Rkey:       rkey,
	})

	// Update session with the latest nonce
	session.DPoPNonce = apiSession.DPoPNonce

	// Audit: Record read
	resourceURI := "at://" + session.DID + "/" + collection + "/" + rkey
	if err != nil {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordRead,
			Actor:     session.DID,
			Action:    "get_record",
			Resource:  resourceURI,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
	} else {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordRead,
			Actor:     session.DID,
			Action:    "get_record",
			Resource:  resourceURI,
			Result:    AuditResultSuccess,
		})
	}

	return record, err
}

// PutRecord creates or updates a record at a specific rkey in the repository.
// Unlike CreateRecord which auto-generates an rkey, PutRecord lets you specify
// the exact rkey, making it useful for updating existing records or creating
// records with deterministic keys.
func (c *Client) PutRecord(ctx context.Context, session *Session, collection, rkey string, record map[string]interface{}) (*atproto.RepoPutRecord_Output, error) {
	if session == nil || session.AccessToken == "" {
		logger := LoggerFromContext(ctx)
		logger.Error("no valid session for PutRecord")
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

	output, err := apiClient.PutRecord(ctx, &api.PutRecordRequest{
		Session:    apiSession,
		Collection: collection,
		Rkey:       rkey,
		Record:     record,
	})

	// Update session with the latest nonce
	session.DPoPNonce = apiSession.DPoPNonce

	// Audit: Record put
	resourceURI := "at://" + session.DID + "/" + collection + "/" + rkey
	if err != nil {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordPut,
			Actor:     session.DID,
			Action:    "put_record",
			Resource:  resourceURI,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
	} else {
		var actualURI string
		if output != nil {
			actualURI = output.Uri
		}
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordPut,
			Actor:     session.DID,
			Action:    "put_record",
			Resource:  actualURI,
			Result:    AuditResultSuccess,
			Metadata: map[string]interface{}{
				"collection": collection,
				"rkey":       rkey,
			},
		})
	}

	return output, err
}

// PutRecordWithSwap creates or updates a record with compare-and-swap semantics.
// swapRecord is the CID of the existing record to replace (for updates).
// swapCommit is the CID of the repo head (for optimistic concurrency).
// Pass empty strings to skip swap checks.
func (c *Client) PutRecordWithSwap(ctx context.Context, session *Session, collection, rkey string, record map[string]interface{}, swapRecord, swapCommit string) (*atproto.RepoPutRecord_Output, error) {
	if session == nil || session.AccessToken == "" {
		logger := LoggerFromContext(ctx)
		logger.Error("no valid session for PutRecordWithSwap")
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

	req := &api.PutRecordRequest{
		Session:    apiSession,
		Collection: collection,
		Rkey:       rkey,
		Record:     record,
	}

	if swapRecord != "" {
		req.SwapRecord = &swapRecord
	}
	if swapCommit != "" {
		req.SwapCommit = &swapCommit
	}

	output, err := apiClient.PutRecord(ctx, req)

	// Update session with the latest nonce
	session.DPoPNonce = apiSession.DPoPNonce

	// Audit: Record put with swap
	resourceURI := "at://" + session.DID + "/" + collection + "/" + rkey
	if err != nil {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordPut,
			Actor:     session.DID,
			Action:    "put_record_swap",
			Resource:  resourceURI,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
	} else {
		var actualURI string
		if output != nil {
			actualURI = output.Uri
		}
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordPut,
			Actor:     session.DID,
			Action:    "put_record_swap",
			Resource:  actualURI,
			Result:    AuditResultSuccess,
			Metadata: map[string]interface{}{
				"collection": collection,
				"rkey":       rkey,
				"swap":       true,
			},
		})
	}

	return output, err
}

// ListRecords lists records in a collection.
// Use opts to specify pagination, limit, and other options.
// Pass nil for opts to use defaults.
func (c *Client) ListRecords(ctx context.Context, session *Session, collection string, opts *ListRecordsOptions) (*ListRecordsResult, error) {
	if session == nil || session.AccessToken == "" {
		logger := LoggerFromContext(ctx)
		logger.Error("no valid session for ListRecords")
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
		ValidateNSID: ValidateCollectionNSID,
	}

	apiSession := &api.Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
		DPoPKey:     session.DPoPKey,
		DPoPNonce:   session.DPoPNonce,
	}

	// Build request from options
	req := &api.ListRecordsRequest{
		Session:    apiSession,
		Collection: collection,
	}

	if opts != nil {
		req.Repo = opts.Repo
		req.Limit = opts.Limit
		req.Cursor = opts.Cursor
		req.Reverse = opts.Reverse
	}

	response, err := apiClient.ListRecords(ctx, req)

	// Update session with the latest nonce
	session.DPoPNonce = apiSession.DPoPNonce

	// Determine the repo being queried
	repo := session.DID
	if opts != nil && opts.Repo != "" {
		repo = opts.Repo
	}

	// Audit: Record list
	if err != nil {
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventRecordList,
			Actor:     session.DID,
			Action:    "list_records",
			Resource:  collection,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
		return nil, err
	}

	// Convert internal response to public type
	result := &ListRecordsResult{
		Records: make([]RecordEntry, len(response.Records)),
		Cursor:  response.Cursor,
	}

	for i, rec := range response.Records {
		result.Records[i] = RecordEntry{
			URI:   rec.URI,
			CID:   rec.CID,
			Value: rec.Value,
		}
	}

	_ = LogAuditEvent(ctx, AuditEvent{
		EventType: AuditEventRecordList,
		Actor:     session.DID,
		Action:    "list_records",
		Resource:  collection,
		Result:    AuditResultSuccess,
		Metadata: map[string]interface{}{
			"repo":     repo,
			"count":    len(result.Records),
			"has_more": result.Cursor != "",
		},
	})

	return result, nil
}

// GetClientMetadata returns the OAuth client metadata as a JSON-serializable map.
func (c *Client) GetClientMetadata() map[string]interface{} {
	return map[string]interface{}{
		"client_id":                  c.ClientID,
		"client_name":                c.ClientName,
		"redirect_uris":              []string{c.RedirectURI},
		"scope":                      strings.Join(c.Scopes, " "),
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
	sessionStoreAdapter := &sessionStoreAdapter{
		store:       c.SessionStore,
		authAdapter: authFlowAdapter, // Wire up the reference so we can get the full session
	}

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
	client      *Client
	lastSession *Session // Store the full session from CompleteAuthFlow
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
	// Store the full session for later retrieval by sessionStoreAdapter
	a.lastSession = session
	return &internalhttp.Session{
		DID:         session.DID,
		AccessToken: session.AccessToken,
	}, nil
}

// sessionStoreAdapter adapts SessionStore to internal interface
type sessionStoreAdapter struct {
	store       SessionStore
	authAdapter *authFlowAdapter // Reference to get the full session
}

func (s *sessionStoreAdapter) Set(sessionID string, session *internalhttp.Session) error {
	// Get the full session from the authAdapter
	// The internal/http.Session only has DID and AccessToken,
	// but we need to store the complete session with DPoPKey, RefreshToken, etc.
	fullSession := s.authAdapter.lastSession
	if fullSession == nil {
		// Fallback to creating a minimal session if we don't have the full one
		fullSession = &Session{
			DID:         session.DID,
			AccessToken: session.AccessToken,
		}
	}
	return s.store.Set(sessionID, fullSession)
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
