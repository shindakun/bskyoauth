package api

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"time"

	"github.com/bluesky-social/indigo/api/atproto"
	"github.com/bluesky-social/indigo/api/bsky"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/bluesky-social/indigo/lex/util"
	"github.com/bluesky-social/indigo/xrpc"

	_ "github.com/shindakun/bskyoauth/lexicon" // Register custom lexicons
)

// Logger interface for API operations
type Logger interface {
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// Session represents an authenticated user session
type Session struct {
	DID         string
	AccessToken string
	DPoPKey     *ecdsa.PrivateKey
	DPoPNonce   string
}

// DPoPTransportFactory creates a DPoP transport for API requests
type DPoPTransportFactory func(underlying http.RoundTripper, dpopKey *ecdsa.PrivateKey, token string, nonce string) http.RoundTripper

// DPoPNonceGetter extracts the current DPoP nonce from a transport
type DPoPNonceGetter interface {
	GetNonce() string
}

// ValidationFunc validates input before API calls
type ValidationFunc func(interface{}) error

// Client handles AT Protocol API operations
type Client struct {
	TransportFactory DPoPTransportFactory
	LoggerGetter     func(context.Context) Logger
	ValidatePostText func(string) error
	ValidateNSID     func(string) error
	ValidateRecord   func(map[string]interface{}) error
}

// CreatePostRequest contains parameters for creating a post
type CreatePostRequest struct {
	Session *Session
	Text    string
}

// CreatePost creates a post on Bluesky
func (c *Client) CreatePost(ctx context.Context, req *CreatePostRequest) error {
	logger := c.LoggerGetter(ctx)
	logger.Info("creating post",
		"did", req.Session.DID,
		"text_length", len(req.Text))

	// Validate post text
	if c.ValidatePostText != nil {
		if err := c.ValidatePostText(req.Text); err != nil {
			logger.Warn("invalid post text",
				"did", req.Session.DID,
				"error", err)
			return fmt.Errorf("invalid post text: %w", err)
		}
	}

	// Get the actual PDS endpoint for this user
	pdsHost, err := c.resolvePDSEndpoint(ctx, req.Session.DID)
	if err != nil {
		return err
	}

	// Create HTTP client with DPoP transport
	transport := c.TransportFactory(http.DefaultTransport, req.Session.DPoPKey, req.Session.AccessToken, req.Session.DPoPNonce)
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
		Text:      req.Text,
		CreatedAt: now.Format(time.RFC3339),
	}

	// Create the post
	input := &atproto.RepoCreateRecord_Input{
		Repo:       req.Session.DID,
		Collection: "app.bsky.feed.post",
		Record: &util.LexiconTypeDecoder{
			Val: record,
		},
	}

	_, err = atproto.RepoCreateRecord(ctx, client, input)

	// Update session with the latest nonce
	if nonceGetter, ok := transport.(DPoPNonceGetter); ok {
		req.Session.DPoPNonce = nonceGetter.GetNonce()
	}

	if err != nil {
		logger.Error("failed to create post",
			"did", req.Session.DID,
			"error", err)
		return err
	}

	logger.Info("post created successfully",
		"did", req.Session.DID)

	return nil
}

// CreateRecordRequest contains parameters for creating a record
type CreateRecordRequest struct {
	Session    *Session
	Collection string
	Record     map[string]interface{}
}

// CreateRecord creates a custom record in the specified collection
func (c *Client) CreateRecord(ctx context.Context, req *CreateRecordRequest) (*atproto.RepoCreateRecord_Output, error) {
	logger := c.LoggerGetter(ctx)
	logger.Info("creating record",
		"did", req.Session.DID,
		"collection", req.Collection)

	// Validate collection NSID
	if c.ValidateNSID != nil {
		if err := c.ValidateNSID(req.Collection); err != nil {
			logger.Warn("invalid collection NSID",
				"did", req.Session.DID,
				"collection", req.Collection,
				"error", err)
			return nil, fmt.Errorf("invalid collection: %w", err)
		}
	}

	// Validate record fields
	if c.ValidateRecord != nil {
		if err := c.ValidateRecord(req.Record); err != nil {
			logger.Warn("invalid record fields",
				"did", req.Session.DID,
				"collection", req.Collection,
				"error", err)
			return nil, fmt.Errorf("invalid record: %w", err)
		}
	}

	// Get the actual PDS endpoint for this user
	pdsHost, err := c.resolvePDSEndpoint(ctx, req.Session.DID)
	if err != nil {
		return nil, err
	}

	// Create HTTP client with DPoP transport
	transport := c.TransportFactory(http.DefaultTransport, req.Session.DPoPKey, req.Session.AccessToken, req.Session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	xrpcClient := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Add $type field to the record if not present
	if _, exists := req.Record["$type"]; !exists {
		req.Record["$type"] = req.Collection
	}

	// Call the XRPC method directly with the raw input
	var output atproto.RepoCreateRecord_Output

	input := map[string]interface{}{
		"repo":       req.Session.DID,
		"collection": req.Collection,
		"record":     req.Record,
	}

	err = xrpcClient.Do(ctx, xrpc.Procedure, "application/json", "com.atproto.repo.createRecord", nil, input, &output)

	// Update session with the latest nonce
	if nonceGetter, ok := transport.(DPoPNonceGetter); ok {
		req.Session.DPoPNonce = nonceGetter.GetNonce()
	}

	if err != nil {
		logger.Error("failed to create record",
			"did", req.Session.DID,
			"collection", req.Collection,
			"error", err)
		return nil, err
	}

	logger.Info("record created successfully",
		"did", req.Session.DID,
		"collection", req.Collection,
		"uri", output.Uri)

	return &output, nil
}

// DeleteRecordRequest contains parameters for deleting a record
type DeleteRecordRequest struct {
	Session    *Session
	Collection string
	Rkey       string
}

// DeleteRecord deletes a record from the repository
func (c *Client) DeleteRecord(ctx context.Context, req *DeleteRecordRequest) error {
	logger := c.LoggerGetter(ctx)
	logger.Info("deleting record",
		"did", req.Session.DID,
		"collection", req.Collection,
		"rkey", req.Rkey)

	// Get the actual PDS endpoint for this user
	pdsHost, err := c.resolvePDSEndpoint(ctx, req.Session.DID)
	if err != nil {
		return err
	}

	// Create HTTP client with DPoP transport
	transport := c.TransportFactory(http.DefaultTransport, req.Session.DPoPKey, req.Session.AccessToken, req.Session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	client := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Delete the record
	input := &atproto.RepoDeleteRecord_Input{
		Repo:       req.Session.DID,
		Collection: req.Collection,
		Rkey:       req.Rkey,
	}

	_, err = atproto.RepoDeleteRecord(ctx, client, input)

	// Update session with the latest nonce
	if nonceGetter, ok := transport.(DPoPNonceGetter); ok {
		req.Session.DPoPNonce = nonceGetter.GetNonce()
	}

	if err != nil {
		logger.Error("failed to delete record",
			"did", req.Session.DID,
			"collection", req.Collection,
			"rkey", req.Rkey,
			"error", err)
		return err
	}

	logger.Info("record deleted successfully",
		"did", req.Session.DID,
		"collection", req.Collection,
		"rkey", req.Rkey)

	return nil
}

// GetRecordRequest contains parameters for getting a record
type GetRecordRequest struct {
	Session    *Session
	Collection string
	Rkey       string
}

// GetRecord retrieves a record from the repository
func (c *Client) GetRecord(ctx context.Context, req *GetRecordRequest) (map[string]interface{}, error) {
	logger := c.LoggerGetter(ctx)
	logger.Info("getting record",
		"did", req.Session.DID,
		"collection", req.Collection,
		"rkey", req.Rkey)

	// Validate collection NSID
	if c.ValidateNSID != nil {
		if err := c.ValidateNSID(req.Collection); err != nil {
			logger.Warn("invalid collection NSID",
				"did", req.Session.DID,
				"collection", req.Collection,
				"error", err)
			return nil, fmt.Errorf("invalid collection: %w", err)
		}
	}

	// Validate rkey is not empty
	if req.Rkey == "" {
		return nil, fmt.Errorf("rkey cannot be empty")
	}

	// Get the actual PDS endpoint for this user
	pdsHost, err := c.resolvePDSEndpoint(ctx, req.Session.DID)
	if err != nil {
		return nil, err
	}

	// Create HTTP client with DPoP transport
	transport := c.TransportFactory(http.DefaultTransport, req.Session.DPoPKey, req.Session.AccessToken, req.Session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	xrpcClient := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Get the record using com.atproto.repo.getRecord
	var output atproto.RepoGetRecord_Output

	params := map[string]interface{}{
		"repo":       req.Session.DID,
		"collection": req.Collection,
		"rkey":       req.Rkey,
	}

	err = xrpcClient.Do(ctx, xrpc.Query, "", "com.atproto.repo.getRecord", params, nil, &output)

	// Update session with the latest nonce
	if nonceGetter, ok := transport.(DPoPNonceGetter); ok {
		req.Session.DPoPNonce = nonceGetter.GetNonce()
	}

	if err != nil {
		logger.Error("failed to get record",
			"did", req.Session.DID,
			"collection", req.Collection,
			"rkey", req.Rkey,
			"error", err)
		return nil, err
	}

	logger.Info("record retrieved successfully",
		"did", req.Session.DID,
		"collection", req.Collection,
		"rkey", req.Rkey,
		"uri", output.Uri)

	// Return the record value directly from the LexiconTypeDecoder
	// The caller can work with this value as needed
	if output.Value != nil && output.Value.Val != nil {
		return map[string]interface{}{
			"value": output.Value.Val,
			"uri":   output.Uri,
			"cid":   output.Cid,
		}, nil
	}

	// No value in output, return empty map with metadata
	return map[string]interface{}{
		"uri": output.Uri,
		"cid": output.Cid,
	}, nil
}

// PutRecordRequest contains parameters for creating or updating a record at a specific rkey
type PutRecordRequest struct {
	Session    *Session
	Collection string
	Rkey       string
	Record     map[string]interface{}
	SwapRecord *string // Optional: CID of the record to swap (for compare-and-swap)
	SwapCommit *string // Optional: CID of the repo commit to swap
}

// PutRecord creates or updates a record at a specific rkey in the repository
func (c *Client) PutRecord(ctx context.Context, req *PutRecordRequest) (*atproto.RepoPutRecord_Output, error) {
	logger := c.LoggerGetter(ctx)
	logger.Info("putting record",
		"did", req.Session.DID,
		"collection", req.Collection,
		"rkey", req.Rkey)

	// Validate collection NSID
	if c.ValidateNSID != nil {
		if err := c.ValidateNSID(req.Collection); err != nil {
			logger.Warn("invalid collection NSID",
				"did", req.Session.DID,
				"collection", req.Collection,
				"error", err)
			return nil, fmt.Errorf("invalid collection: %w", err)
		}
	}

	// Validate rkey is not empty
	if req.Rkey == "" {
		return nil, fmt.Errorf("rkey cannot be empty")
	}

	// Validate record fields
	if c.ValidateRecord != nil {
		if err := c.ValidateRecord(req.Record); err != nil {
			logger.Warn("invalid record fields",
				"did", req.Session.DID,
				"collection", req.Collection,
				"error", err)
			return nil, fmt.Errorf("invalid record: %w", err)
		}
	}

	// Get the actual PDS endpoint for this user
	pdsHost, err := c.resolvePDSEndpoint(ctx, req.Session.DID)
	if err != nil {
		return nil, err
	}

	// Create HTTP client with DPoP transport
	transport := c.TransportFactory(http.DefaultTransport, req.Session.DPoPKey, req.Session.AccessToken, req.Session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	xrpcClient := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Add $type field to the record if not present
	if _, exists := req.Record["$type"]; !exists {
		req.Record["$type"] = req.Collection
	}

	// Build the input map
	input := map[string]interface{}{
		"repo":       req.Session.DID,
		"collection": req.Collection,
		"rkey":       req.Rkey,
		"record":     req.Record,
	}

	// Add optional swap parameters
	if req.SwapRecord != nil {
		input["swapRecord"] = *req.SwapRecord
	}
	if req.SwapCommit != nil {
		input["swapCommit"] = *req.SwapCommit
	}

	// Call the XRPC method
	var output atproto.RepoPutRecord_Output
	err = xrpcClient.Do(ctx, xrpc.Procedure, "application/json", "com.atproto.repo.putRecord", nil, input, &output)

	// Update session with the latest nonce
	if nonceGetter, ok := transport.(DPoPNonceGetter); ok {
		req.Session.DPoPNonce = nonceGetter.GetNonce()
	}

	if err != nil {
		logger.Error("failed to put record",
			"did", req.Session.DID,
			"collection", req.Collection,
			"rkey", req.Rkey,
			"error", err)
		return nil, err
	}

	logger.Info("record put successfully",
		"did", req.Session.DID,
		"collection", req.Collection,
		"rkey", req.Rkey,
		"uri", output.Uri)

	return &output, nil
}

// ListRecordsRequest contains parameters for listing records in a collection
type ListRecordsRequest struct {
	Session    *Session
	Repo       string // DID of the repo to list from (defaults to session DID if empty)
	Collection string
	Limit      int    // Max number of records to return (default 50, max 100)
	Cursor     string // Pagination cursor
	Reverse    bool   // Return results in reverse order
}

// RecordEntry represents a single record in a list response
type RecordEntry struct {
	URI   string
	CID   string
	Value interface{}
}

// ListRecordsResponse contains the response from listing records
type ListRecordsResponse struct {
	Records []RecordEntry
	Cursor  string // Cursor for next page, empty if no more results
}

// ListRecords lists records in a collection
func (c *Client) ListRecords(ctx context.Context, req *ListRecordsRequest) (*ListRecordsResponse, error) {
	logger := c.LoggerGetter(ctx)

	// Default repo to session DID
	repo := req.Repo
	if repo == "" {
		repo = req.Session.DID
	}

	logger.Info("listing records",
		"repo", repo,
		"collection", req.Collection,
		"limit", req.Limit,
		"cursor", req.Cursor)

	// Validate collection NSID
	if c.ValidateNSID != nil {
		if err := c.ValidateNSID(req.Collection); err != nil {
			logger.Warn("invalid collection NSID",
				"repo", repo,
				"collection", req.Collection,
				"error", err)
			return nil, fmt.Errorf("invalid collection: %w", err)
		}
	}

	// Get the actual PDS endpoint for the target repo
	pdsHost, err := c.resolvePDSEndpoint(ctx, repo)
	if err != nil {
		return nil, err
	}

	// Create HTTP client with DPoP transport
	transport := c.TransportFactory(http.DefaultTransport, req.Session.DPoPKey, req.Session.AccessToken, req.Session.DPoPNonce)
	httpClient := &http.Client{
		Transport: transport,
	}

	xrpcClient := &xrpc.Client{
		Host:   pdsHost,
		Client: httpClient,
	}

	// Build query parameters
	params := map[string]interface{}{
		"repo":       repo,
		"collection": req.Collection,
	}

	if req.Limit > 0 {
		// Clamp limit to max 100
		limit := req.Limit
		if limit > 100 {
			limit = 100
		}
		params["limit"] = int64(limit)
	}

	if req.Cursor != "" {
		params["cursor"] = req.Cursor
	}

	if req.Reverse {
		params["reverse"] = true
	}

	// Call the XRPC method
	var output atproto.RepoListRecords_Output
	err = xrpcClient.Do(ctx, xrpc.Query, "", "com.atproto.repo.listRecords", params, nil, &output)

	// Update session with the latest nonce
	if nonceGetter, ok := transport.(DPoPNonceGetter); ok {
		req.Session.DPoPNonce = nonceGetter.GetNonce()
	}

	if err != nil {
		logger.Error("failed to list records",
			"repo", repo,
			"collection", req.Collection,
			"error", err)
		return nil, err
	}

	// Convert to our response type
	response := &ListRecordsResponse{
		Records: make([]RecordEntry, len(output.Records)),
	}

	for i, rec := range output.Records {
		var value interface{}
		if rec.Value != nil {
			value = rec.Value.Val
		}
		response.Records[i] = RecordEntry{
			URI:   rec.Uri,
			CID:   rec.Cid,
			Value: value,
		}
	}

	if output.Cursor != nil {
		response.Cursor = *output.Cursor
	}

	logger.Info("records listed successfully",
		"repo", repo,
		"collection", req.Collection,
		"count", len(response.Records),
		"has_more", response.Cursor != "")

	return response, nil
}

// resolvePDSEndpoint resolves the PDS endpoint for a given DID
func (c *Client) resolvePDSEndpoint(ctx context.Context, did string) (string, error) {
	dir := identity.DefaultDirectory()
	atid, err := syntax.ParseAtIdentifier(did)
	if err != nil {
		return "", err
	}

	ident, err := dir.Lookup(ctx, *atid)
	if err != nil {
		return "", err
	}

	return ident.PDSEndpoint(), nil
}
