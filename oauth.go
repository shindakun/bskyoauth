package bskyoauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

var (
	// ErrInvalidHandle is returned when the handle cannot be parsed or resolved
	ErrInvalidHandle = errors.New("invalid handle")

	// ErrInvalidState is returned when the OAuth state parameter is invalid
	ErrInvalidState = errors.New("invalid state parameter")

	// ErrTokenExchange is returned when token exchange fails
	ErrTokenExchange = errors.New("token exchange failed")

	// ErrNoAccessToken is returned when no access token is received
	ErrNoAccessToken = errors.New("no access token in response")

	// ErrIssuerMismatch is returned when the callback issuer doesn't match the expected authorization server
	ErrIssuerMismatch = errors.New("issuer mismatch: potential authorization code injection attack")
)

// oauthStateStore stores temporary OAuth state for PKCE and DPoP keys with TTL
type oauthStateStore struct {
	states          map[string]*stateEntry
	mu              sync.RWMutex
	ttl             time.Duration
	cleanupInterval time.Duration
	stopCh          chan struct{}
	stopped         bool
}

type stateEntry struct {
	state     *internalOAuthState
	expiresAt time.Time
}

type internalOAuthState struct {
	CodeVerifier   string
	DPoPKey        interface{} // *ecdsa.PrivateKey
	ExpectedIssuer string      // Expected authorization server for validation
	DID            string      // User's DID for session creation
}

const (
	// DefaultStateStoreTTL is the default time-to-live for OAuth state entries (10 minutes)
	DefaultStateStoreTTL = 10 * time.Minute
	// DefaultCleanupInterval is how often the cleanup goroutine runs (1 minute)
	DefaultCleanupInterval = 1 * time.Minute
)

var globalStateStore = newOAuthStateStore(DefaultStateStoreTTL)

// newOAuthStateStore creates a new OAuth state store with the given TTL
func newOAuthStateStore(ttl time.Duration) *oauthStateStore {
	return newOAuthStateStoreWithInterval(ttl, DefaultCleanupInterval)
}

// newOAuthStateStoreWithInterval creates a new OAuth state store with custom TTL and cleanup interval
func newOAuthStateStoreWithInterval(ttl, cleanupInterval time.Duration) *oauthStateStore {
	store := &oauthStateStore{
		states:          make(map[string]*stateEntry),
		ttl:             ttl,
		cleanupInterval: cleanupInterval,
		stopCh:          make(chan struct{}),
	}
	go store.cleanupExpired()
	return store
}

func (s *oauthStateStore) set(state string, oauth *internalOAuthState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states[state] = &stateEntry{
		state:     oauth,
		expiresAt: time.Now().Add(s.ttl),
	}
}

func (s *oauthStateStore) get(state string) (*internalOAuthState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.states[state]
	if !exists {
		return nil, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry.state, true
}

func (s *oauthStateStore) delete(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.states, state)
}

// cleanupExpired removes expired entries from the store
func (s *oauthStateStore) cleanupExpired() {
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for key, entry := range s.states {
				if now.After(entry.expiresAt) {
					delete(s.states, key)
				}
			}
			s.mu.Unlock()
		case <-s.stopCh:
			return
		}
	}
}

// stop gracefully stops the cleanup goroutine (used for testing/shutdown)
func (s *oauthStateStore) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.stopped {
		close(s.stopCh)
		s.stopped = true
	}
}

// StartAuthFlow initiates the OAuth authorization flow for a given handle.
// Returns an AuthFlowState with the authorization URL and state information.
func (c *Client) StartAuthFlow(ctx context.Context, handle string) (*AuthFlowState, error) {
	logger := LoggerFromContext(ctx)
	logger.Info("starting OAuth flow",
		"handle", handle,
		"client_id", c.ClientID)

	// Generate DPoP key pair
	dpopKey, err := GenerateDPoPKey()
	if err != nil {
		logger.Error("failed to generate DPoP key",
			"handle", handle,
			"error", err)
		return nil, fmt.Errorf("failed to generate DPoP key: %w", err)
	}

	// Generate PKCE challenge
	codeVerifier := generateCodeVerifier()
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Generate state
	state := generateRandomString(32)

	// Resolve handle to DID and authorization server
	dir := identity.DefaultDirectory()
	atid, err := syntax.ParseAtIdentifier(handle)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHandle, err)
	}

	ident, err := dir.Lookup(ctx, *atid)
	if err != nil {
		logger.Warn("handle lookup failed",
			"handle", handle,
			"error", err)
		return nil, fmt.Errorf("%w: %v", ErrInvalidHandle, err)
	}

	// For bsky.social users, use bsky.social as the authorization server
	// For other PDS instances, use the PDS endpoint
	authServer := ident.PDSEndpoint()
	if strings.Contains(authServer, "bsky.network") || strings.Contains(string(ident.DID), "bsky.social") {
		authServer = "https://bsky.social"
	}

	// Store OAuth state with expected issuer for validation
	globalStateStore.set(state, &internalOAuthState{
		CodeVerifier:   codeVerifier,
		DPoPKey:        dpopKey,
		ExpectedIssuer: authServer,
		DID:            string(ident.DID),
	})

	metadataURL := authServer + "/.well-known/oauth-authorization-server"

	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth server metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// Log detailed error internally for debugging/monitoring
		logger.Error("auth server metadata request failed",
			"handle", handle,
			"url", metadataURL,
			"status", resp.Status,
			"body", string(body))
		// Return generic error to user to prevent information disclosure
		return nil, fmt.Errorf("failed to retrieve authorization server metadata (status: %d)", resp.StatusCode)
	}

	var metadata AuthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	if metadata.AuthorizationEndpoint == "" {
		return nil, errors.New("no authorization endpoint in metadata")
	}

	// Build authorization URL
	authURL, _ := url.Parse(metadata.AuthorizationEndpoint)
	q := authURL.Query()
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "atproto transition:generic")
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("login_hint", string(ident.DID))
	authURL.RawQuery = q.Encode()

	logger.Info("OAuth flow started successfully",
		"handle", handle,
		"did", string(ident.DID),
		"auth_server", authServer)

	return &AuthFlowState{
		State:        state,
		CodeVerifier: codeVerifier,
		DPoPKey:      dpopKey,
		AuthURL:      authURL.String(),
		DID:          string(ident.DID),
	}, nil
}

// CompleteAuthFlow completes the OAuth flow by exchanging the authorization code for tokens.
func (c *Client) CompleteAuthFlow(ctx context.Context, code, state, issuer string) (*Session, error) {
	logger := LoggerFromContext(ctx)
	logger.Info("completing OAuth flow",
		"issuer", issuer)

	// Retrieve OAuth state
	oauthState, exists := globalStateStore.get(state)
	if !exists {
		logger.Warn("invalid or expired OAuth state",
			"state", state,
			"issuer", issuer)
		return nil, ErrInvalidState
	}
	globalStateStore.delete(state)

	// Validate issuer matches expected authorization server
	// This prevents authorization code injection attacks
	if issuer != oauthState.ExpectedIssuer {
		// Log security event for monitoring
		logger.Error("SECURITY: issuer mismatch detected",
			"expected_issuer", oauthState.ExpectedIssuer,
			"received_issuer", issuer,
			"did", oauthState.DID)
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrIssuerMismatch,
			oauthState.ExpectedIssuer, issuer)
	}

	// Get token endpoint from issuer
	metadataURL := issuer + "/.well-known/oauth-authorization-server"
	resp, err := http.Get(metadataURL)
	if err != nil {
		logger.Error("failed to get auth server metadata for token exchange",
			"issuer", issuer,
			"error", err)
		return nil, fmt.Errorf("failed to get auth server metadata: %w", err)
	}
	defer resp.Body.Close()

	var metadata AuthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		logger.Error("failed to decode auth server metadata",
			"issuer", issuer,
			"error", err)
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	if metadata.TokenEndpoint == "" {
		logger.Error("no token endpoint in metadata",
			"issuer", issuer)
		return nil, errors.New("no token endpoint in metadata")
	}

	// Exchange code for tokens with DPoP
	tokens, err := c.exchangeCodeForTokens(ctx, metadata.TokenEndpoint, code, oauthState.CodeVerifier, oauthState.DPoPKey)
	if err != nil {
		logger.Error("token exchange failed",
			"issuer", issuer,
			"token_endpoint", metadata.TokenEndpoint,
			"error", err)
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}

	// Check if access_token exists
	accessToken, ok := tokens["access_token"].(string)
	if !ok || accessToken == "" {
		tokensJSON, _ := json.Marshal(tokens)
		logger.Error("no access token in token exchange response",
			"issuer", issuer,
			"response", string(tokensJSON))
		return nil, fmt.Errorf("%w: %s", ErrNoAccessToken, string(tokensJSON))
	}

	// Extract DID from token
	// Per AT Protocol spec, access tokens are opaque from client perspective,
	// but in practice they're JWTs. We parse to extract the DID for session management.
	// Note: We do NOT validate the signature - validation happens server-side when used.
	var sub string
	parts := strings.Split(accessToken, ".")
	if len(parts) == 3 {
		// Token appears to be a JWT, try to parse it
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err == nil {
			var claims map[string]interface{}
			if err := json.Unmarshal(payload, &claims); err == nil {
				if s, ok := claims["sub"].(string); ok {
					sub = s
				}
			}
		}
	}

	// If we couldn't extract DID from token, that's okay - use the DID from OAuth state
	// The token will be validated by the PDS when we make our first API call
	if sub == "" {
		sub = oauthState.DID
	}

	refreshToken, _ := tokens["refresh_token"].(string)

	// Create session
	session := &Session{
		DID:          sub,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		DPoPKey:      oauthState.DPoPKey.(*ecdsa.PrivateKey),
		PDS:          issuer,
	}

	logger.Info("OAuth flow completed successfully",
		"did", sub,
		"issuer", issuer,
		"has_refresh_token", refreshToken != "")

	return session, nil
}

// exchangeCodeForTokens exchanges an authorization code for access and refresh tokens.
func (c *Client) exchangeCodeForTokens(ctx context.Context, tokenEndpoint, code, codeVerifier string, dpopKey interface{}) (map[string]interface{}, error) {
	logger := LoggerFromContext(ctx)
	// First attempt without nonce to get the nonce
	dpopProof, err := createDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", "")
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.RedirectURI)
	data.Set("client_id", c.ClientID)
	data.Set("code_verifier", codeVerifier)

	req, _ := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("DPoP", dpopProof)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Check if we need to retry with nonce
	if resp.StatusCode == http.StatusBadRequest {
		var errorResp map[string]interface{}
		if err := json.Unmarshal(body, &errorResp); err == nil {
			if errorResp["error"] == "use_dpop_nonce" {
				// Get nonce from header and retry
				nonce := resp.Header.Get("DPoP-Nonce")
				if nonce != "" {
					logger.Info("retrying token exchange with DPoP nonce",
						"token_endpoint", tokenEndpoint)
					// Retry with nonce
					dpopProof, err = createDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", nonce)
					if err != nil {
						return nil, err
					}

					req, _ = http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					req.Header.Set("DPoP", dpopProof)

					resp, err = client.Do(req)
					if err != nil {
						return nil, err
					}
					defer resp.Body.Close()

					body, _ = io.ReadAll(resp.Body)
				}
			}
		}
	}

	if resp.StatusCode != http.StatusOK {
		// Log detailed error internally for debugging/monitoring
		logger.Error("token exchange failed",
			"token_endpoint", tokenEndpoint,
			"status", resp.Status,
			"body", string(body))
		// Return generic error to user to prevent information disclosure
		return nil, fmt.Errorf("token exchange failed (status: %d)", resp.StatusCode)
	}

	var tokens map[string]interface{}
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, err
	}

	return tokens, nil
}

// generateCodeVerifier generates a PKCE code verifier.
func generateCodeVerifier() string {
	return generateRandomString(64)
}

// generateCodeChallenge generates a PKCE code challenge from a verifier.
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
