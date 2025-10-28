package bskyoauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/xrpc"
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

	// Scopes are the OAuth scopes to request (optional, defaults to ["atproto", "transition:generic"])
	Scopes []string

	// SessionStore is the storage backend for sessions (optional, defaults to in-memory store)
	SessionStore SessionStore
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

	// Remove trailing slash from BaseURL to avoid double slashes
	baseURL := opts.BaseURL
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	return &Client{
		BaseURL:      baseURL,
		ClientID:     baseURL + "/client-metadata.json",
		RedirectURI:  baseURL + "/callback",
		ClientName:   opts.ClientName,
		Scopes:       opts.Scopes,
		SessionStore: opts.SessionStore,
	}
}

// CreatePost creates a post on Bluesky using the provided session.
func (c *Client) CreatePost(ctx context.Context, session *Session, text string) error {
	if session == nil || session.AccessToken == "" {
		return ErrNoSession
	}

	// Get the actual PDS endpoint for this user
	dir := identity.DefaultDirectory()
	atid, err := syntax.ParseAtIdentifier(session.DID)
	if err != nil {
		return err
	}

	ident, err := dir.Lookup(ctx, *atid)
	if err != nil {
		return err
	}

	pdsHost := ident.PDSEndpoint()

	// Create HTTP client with DPoP transport, reusing the session's nonce
	transport := NewDPoPTransport(http.DefaultTransport, session.DPoPKey, session.AccessToken, session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	client := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Create post record
	now := time.Now()
	record := &bsky.FeedPost{
		Text:      text,
		CreatedAt: now.Format(time.RFC3339),
	}

	// Create the post
	input := &atproto.RepoCreateRecord_Input{
		Repo:       session.DID,
		Collection: "app.bsky.feed.post",
		Record: &util.LexiconTypeDecoder{
			Val: record,
		},
	}

	_, err = atproto.RepoCreateRecord(ctx, client, input)

	// Update session with the latest nonce
	if dpopTransport, ok := transport.(*dpopTransport); ok {
		session.DPoPNonce = dpopTransport.GetNonce()
	}

	return err
}

// CreateRecord creates a custom record in the specified collection.
// This is a low-level method that allows creating any type of record.
// The record parameter should be a map[string]interface{} for custom types.
func (c *Client) CreateRecord(ctx context.Context, session *Session, collection string, record map[string]interface{}) (*atproto.RepoCreateRecord_Output, error) {
	if session == nil || session.AccessToken == "" {
		return nil, ErrNoSession
	}

	// Get the actual PDS endpoint for this user
	dir := identity.DefaultDirectory()
	atid, err := syntax.ParseAtIdentifier(session.DID)
	if err != nil {
		return nil, err
	}

	ident, err := dir.Lookup(ctx, *atid)
	if err != nil {
		return nil, err
	}

	pdsHost := ident.PDSEndpoint()

	// Create HTTP client with DPoP transport, reusing the session's nonce
	transport := NewDPoPTransport(http.DefaultTransport, session.DPoPKey, session.AccessToken, session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	xrpcClient := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Add $type field to the record if not present
	if _, exists := record["$type"]; !exists {
		record["$type"] = collection
	}

	// Call the XRPC method directly with the raw input
	var output atproto.RepoCreateRecord_Output

	input := map[string]interface{}{
		"repo":       session.DID,
		"collection": collection,
		"record":     record,
	}

	err = xrpcClient.Do(ctx, xrpc.Procedure, "application/json", "com.atproto.repo.createRecord", nil, input, &output)

	// Update session with the latest nonce
	if dpopTransport, ok := transport.(*dpopTransport); ok {
		session.DPoPNonce = dpopTransport.GetNonce()
	}

	if err != nil {
		return nil, err
	}

	return &output, nil
}

// DeleteRecord deletes a record from the repository.
func (c *Client) DeleteRecord(ctx context.Context, session *Session, collection, rkey string) error {
	if session == nil || session.AccessToken == "" {
		return ErrNoSession
	}

	// Get the actual PDS endpoint for this user
	dir := identity.DefaultDirectory()
	atid, err := syntax.ParseAtIdentifier(session.DID)
	if err != nil {
		return err
	}

	ident, err := dir.Lookup(ctx, *atid)
	if err != nil {
		return err
	}

	pdsHost := ident.PDSEndpoint()

	// Create HTTP client with DPoP transport, reusing the session's nonce
	transport := NewDPoPTransport(http.DefaultTransport, session.DPoPKey, session.AccessToken, session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	client := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Delete the record
	input := &atproto.RepoDeleteRecord_Input{
		Repo:       session.DID,
		Collection: collection,
		Rkey:       rkey,
	}

	_, err = atproto.RepoDeleteRecord(ctx, client, input)

	// Update session with the latest nonce
	if dpopTransport, ok := transport.(*dpopTransport); ok {
		session.DPoPNonce = dpopTransport.GetNonce()
	}

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
		"application_type":           "web",
		"dpop_bound_access_tokens":   true,
	}
}

// ClientMetadataHandler returns an HTTP handler that serves the OAuth client metadata.
func (c *Client) ClientMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(c.GetClientMetadata())
	}
}

// LoginHandler returns an HTTP handler that initiates the OAuth flow.
// Query parameter: handle (required) - the user's Bluesky handle
func (c *Client) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handle := r.URL.Query().Get("handle")
		if handle == "" {
			http.Error(w, "handle parameter required", http.StatusBadRequest)
			return
		}

		flowState, err := c.StartAuthFlow(r.Context(), handle)
		if err != nil {
			http.Error(w, "Failed to start auth flow: "+err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, flowState.AuthURL, http.StatusFound)
	}
}

// CallbackHandler returns an HTTP handler that completes the OAuth flow.
// Query parameters: code, state, iss (all required)
// On success, creates a session and calls the success handler with the session ID.
func (c *Client) CallbackHandler(onSuccess func(w http.ResponseWriter, r *http.Request, sessionID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check for error response first
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			errDesc := r.URL.Query().Get("error_description")
			http.Error(w, "OAuth error: "+errParam+" - "+errDesc, http.StatusBadRequest)
			return
		}

		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")
		iss := r.URL.Query().Get("iss")

		if code == "" || state == "" {
			// Log all query parameters for debugging
			http.Error(w, "Missing code or state. Received params: "+r.URL.RawQuery, http.StatusBadRequest)
			return
		}

		session, err := c.CompleteAuthFlow(r.Context(), code, state, iss)
		if err != nil {
			http.Error(w, "Failed to complete auth flow: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Generate session ID and store
		sessionID := GenerateSessionID()
		if err := c.SessionStore.Set(sessionID, session); err != nil {
			http.Error(w, "Failed to store session: "+err.Error(), http.StatusInternalServerError)
			return
		}

		onSuccess(w, r, sessionID)
	}
}

// GetSession retrieves a session by ID from the session store.
func (c *Client) GetSession(sessionID string) (*Session, error) {
	return c.SessionStore.Get(sessionID)
}

// DeleteSession removes a session by ID from the session store.
func (c *Client) DeleteSession(sessionID string) error {
	return c.SessionStore.Delete(sessionID)
}
