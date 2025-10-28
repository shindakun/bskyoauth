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
	"os"
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
	// Generate DPoP key pair
	dpopKey, err := GenerateDPoPKey()
	if err != nil {
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
	})

	metadataURL := authServer + "/.well-known/oauth-authorization-server"

	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth server metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("auth server metadata request failed: %s - %s", resp.Status, string(body))
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
	// Retrieve OAuth state
	oauthState, exists := globalStateStore.get(state)
	if !exists {
		return nil, ErrInvalidState
	}
	globalStateStore.delete(state)

	// Validate issuer matches expected authorization server
	// This prevents authorization code injection attacks
	if issuer != oauthState.ExpectedIssuer {
		// Log security event for monitoring
		fmt.Fprintf(os.Stderr, "SECURITY: Issuer mismatch detected - expected: %s, got: %s\n",
			oauthState.ExpectedIssuer, issuer)
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrIssuerMismatch,
			oauthState.ExpectedIssuer, issuer)
	}

	// Get token endpoint from issuer
	metadataURL := issuer + "/.well-known/oauth-authorization-server"
	resp, err := http.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth server metadata: %w", err)
	}
	defer resp.Body.Close()

	var metadata AuthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	if metadata.TokenEndpoint == "" {
		return nil, errors.New("no token endpoint in metadata")
	}

	// Exchange code for tokens with DPoP
	tokens, err := c.exchangeCodeForTokens(metadata.TokenEndpoint, code, oauthState.CodeVerifier, oauthState.DPoPKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}

	// Check if access_token exists
	accessToken, ok := tokens["access_token"].(string)
	if !ok || accessToken == "" {
		tokensJSON, _ := json.Marshal(tokens)
		return nil, fmt.Errorf("%w: %s", ErrNoAccessToken, string(tokensJSON))
	}

	// Get DID from token
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT format")
	}

	// Decode payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token payload: %w", err)
	}

	// Parse claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	// Extract DID from sub claim
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		claimsJSON, _ := json.Marshal(claims)
		return nil, fmt.Errorf("no sub claim in token, claims: %s", string(claimsJSON))
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

	return session, nil
}

// exchangeCodeForTokens exchanges an authorization code for access and refresh tokens.
func (c *Client) exchangeCodeForTokens(tokenEndpoint, code, codeVerifier string, dpopKey interface{}) (map[string]interface{}, error) {
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
		return nil, fmt.Errorf("token request failed: %s - %s", resp.Status, string(body))
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
