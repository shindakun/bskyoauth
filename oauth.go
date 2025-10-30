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
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"

	"github.com/shindakun/bskyoauth/internal/dpop"
	"github.com/shindakun/bskyoauth/internal/oauth"
)

var (
	// defaultHTTPClient is the HTTP client used for OAuth and API requests.
	// Configurable via SetHTTPClient() for testing or custom configurations.
	defaultHTTPClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second, // Connection timeout
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
		},
	}
)

// SetHTTPClient sets a custom HTTP client for all requests.
// Useful for testing or custom timeout/transport configurations.
func SetHTTPClient(client *http.Client) {
	defaultHTTPClient = client
}

// GetHTTPClient returns the current HTTP client.
func GetHTTPClient() *http.Client {
	return defaultHTTPClient
}

// globalStateStore is the package-level OAuth state store.
// Uses internal/oauth.StateStore for implementation.
var globalStateStore = oauth.NewStateStore(oauth.DefaultTTL)

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
	state := dpop.GenerateRandomString(32)

	// Resolve handle to DID and authorization server
	dir := identity.DefaultDirectory()
	atid, err := syntax.ParseAtIdentifier(handle)
	if err != nil {
		// Audit: Auth start failure
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventAuthStart,
			Action:    "start_oauth_flow",
			Resource:  handle,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("%w: %v", ErrInvalidHandle, err)
	}

	ident, err := dir.Lookup(ctx, *atid)
	if err != nil {
		logger.Warn("handle lookup failed",
			"handle", handle,
			"error", err)
		// Audit: Auth start failure
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventAuthStart,
			Action:    "start_oauth_flow",
			Resource:  handle,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("%w: %v", ErrInvalidHandle, err)
	}

	// For bsky.social users, use bsky.social as the authorization server
	// For other PDS instances, use the PDS endpoint
	authServer := ident.PDSEndpoint()
	if strings.Contains(authServer, "bsky.network") || strings.Contains(string(ident.DID), "bsky.social") {
		authServer = "https://bsky.social"
	}

	// Store OAuth state with expected issuer for validation
	globalStateStore.Set(state, &oauth.State{
		CodeVerifier:   codeVerifier,
		DPoPKey:        dpopKey,
		ExpectedIssuer: authServer,
		DID:            string(ident.DID),
	})

	metadataURL := authServer + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		logger.Error("failed to create metadata request",
			"url", metadataURL,
			"error", err)
		return nil, fmt.Errorf("failed to create metadata request: %w", err)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		if IsTimeoutError(err) {
			logger.Error("auth server metadata request timeout",
				"url", metadataURL,
				"error", err)
		}
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

	// Audit: Auth start success
	_ = LogAuditEvent(ctx, AuditEvent{
		EventType: AuditEventAuthStart,
		Actor:     string(ident.DID),
		Action:    "start_oauth_flow",
		Resource:  handle,
		Result:    AuditResultSuccess,
	})

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

	// Audit: OAuth callback received
	_ = LogAuditEvent(ctx, AuditEvent{
		EventType: AuditEventAuthCallback,
		Action:    "oauth_callback_received",
		Resource:  issuer,
		Result:    AuditResultSuccess,
	})

	// Retrieve OAuth state
	oauthState, exists := globalStateStore.Get(state)
	if !exists {
		logger.Warn("invalid or expired OAuth state",
			"state", state,
			"issuer", issuer)
		// Audit: Invalid state (security event)
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventSecurityInvalidState,
			Action:    "oauth_callback_invalid_state",
			Resource:  issuer,
			Result:    AuditResultFailure,
			Error:     "invalid or expired OAuth state",
		})
		return nil, ErrInvalidState
	}
	globalStateStore.Delete(state)

	// Validate issuer matches expected authorization server
	// This prevents authorization code injection attacks
	if issuer != oauthState.ExpectedIssuer {
		// Log security event for monitoring
		logger.Error("SECURITY: issuer mismatch detected",
			"expected_issuer", oauthState.ExpectedIssuer,
			"received_issuer", issuer,
			"did", oauthState.DID)
		// Audit: Issuer mismatch (critical security event)
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventSecurityIssuerMismatch,
			Actor:     oauthState.DID,
			Action:    "oauth_callback_issuer_mismatch",
			Resource:  issuer,
			Result:    AuditResultFailure,
			Error:     fmt.Sprintf("expected %s, got %s", oauthState.ExpectedIssuer, issuer),
			Metadata: map[string]interface{}{
				"expected_issuer": oauthState.ExpectedIssuer,
				"received_issuer": issuer,
			},
		})
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrIssuerMismatch,
			oauthState.ExpectedIssuer, issuer)
	}

	// Get token endpoint from issuer
	metadataURL := issuer + "/.well-known/oauth-authorization-server"

	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		logger.Error("failed to create metadata request for token exchange",
			"issuer", issuer,
			"error", err)
		return nil, fmt.Errorf("failed to create metadata request: %w", err)
	}

	resp, err := defaultHTTPClient.Do(req)
	if err != nil {
		if IsTimeoutError(err) {
			logger.Error("auth server metadata request timeout for token exchange",
				"issuer", issuer,
				"error", err)
		} else {
			logger.Error("failed to get auth server metadata for token exchange",
				"issuer", issuer,
				"error", err)
		}
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

	// Exchange code for tokens with DPoP using internal package
	tokenExchanger := &oauth.TokenExchanger{
		ClientID:     c.ClientID,
		RedirectURI:  c.RedirectURI,
		HTTPClient:   defaultHTTPClient,
		LoggerGetter: func(ctx context.Context) oauth.Logger { return LoggerFromContext(ctx) },
	}

	tokens, err := tokenExchanger.ExchangeCodeForTokens(ctx, metadata.TokenEndpoint, code, oauthState.CodeVerifier, oauthState.DPoPKey)
	if err != nil {
		logger.Error("token exchange failed",
			"issuer", issuer,
			"token_endpoint", metadata.TokenEndpoint,
			"error", err)
		// Audit: Auth failure
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventAuthFailure,
			Actor:     oauthState.DID,
			Action:    "oauth_token_exchange",
			Resource:  issuer,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
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

	// Parse token expiration times
	if expiresIn, ok := tokens["expires_in"].(float64); ok {
		session.AccessTokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
		logger.Info("access token expiration parsed",
			"expires_in_seconds", expiresIn,
			"expires_at", session.AccessTokenExpiresAt)
	}

	if refreshExpiresIn, ok := tokens["refresh_expires_in"].(float64); ok {
		session.RefreshTokenExpiresAt = time.Now().Add(time.Duration(refreshExpiresIn) * time.Second)
		logger.Info("refresh token expiration parsed",
			"refresh_expires_in_seconds", refreshExpiresIn,
			"refresh_expires_at", session.RefreshTokenExpiresAt)
	}

	logger.Info("OAuth flow completed successfully",
		"did", sub,
		"issuer", issuer,
		"has_refresh_token", refreshToken != "")

	// Audit: Auth success
	_ = LogAuditEvent(ctx, AuditEvent{
		EventType: AuditEventAuthSuccess,
		Actor:     sub,
		Action:    "complete_oauth_flow",
		Resource:  issuer,
		Result:    AuditResultSuccess,
	})

	return session, nil
}

// RefreshToken exchanges a refresh token for new access and refresh tokens.
// Per AT Protocol spec, refresh tokens are single-use - the old refresh token
// becomes invalid after a successful refresh.
// The session is updated with new tokens and expiration times.
func (c *Client) RefreshToken(ctx context.Context, session *Session) (*Session, error) {
	logger := LoggerFromContext(ctx)
	logger.Info("refreshing access token",
		"did", session.DID)

	// Validate refresh token using internal package
	if err := oauth.ValidateRefreshToken(session.RefreshToken, session.RefreshTokenExpiresAt); err != nil {
		logger.Error("refresh token validation failed",
			"did", session.DID,
			"error", err)
		return nil, err
	}

	// Fetch metadata from PDS
	metadataFetcher := &oauth.MetadataFetcher{
		HTTPClient:     defaultHTTPClient,
		LoggerGetter:   func(ctx context.Context) oauth.Logger { return LoggerFromContext(ctx) },
		IsTimeoutError: IsTimeoutError,
	}

	metadata, err := metadataFetcher.FetchAuthServerMetadata(ctx, session.PDS)
	if err != nil {
		return nil, err
	}

	if metadata.TokenEndpoint == "" {
		logger.Error("no token endpoint in metadata",
			"pds", session.PDS)
		return nil, errors.New("no token endpoint in metadata")
	}

	// Perform refresh token request with DPoP using internal package
	tokenExchanger := &oauth.TokenExchanger{
		ClientID:     c.ClientID,
		RedirectURI:  c.RedirectURI,
		HTTPClient:   defaultHTTPClient,
		LoggerGetter: func(ctx context.Context) oauth.Logger { return LoggerFromContext(ctx) },
	}

	tokens, err := tokenExchanger.RefreshTokenRequest(ctx, metadata.TokenEndpoint, session.RefreshToken, session.DPoPKey, session.DPoPNonce)
	if err != nil {
		logger.Error("token refresh failed",
			"did", session.DID,
			"error", err)
		// Audit: Token refresh failure
		_ = LogAuditEvent(ctx, AuditEvent{
			EventType: AuditEventSessionRefresh,
			Actor:     session.DID,
			Action:    "refresh_access_token",
			Resource:  session.PDS,
			Result:    AuditResultFailure,
			Error:     err.Error(),
		})
		return nil, fmt.Errorf("token refresh failed: %w", err)
	}

	// Extract new tokens
	newAccessToken, ok := tokens["access_token"].(string)
	if !ok || newAccessToken == "" {
		logger.Error("no access token in refresh response",
			"did", session.DID)
		return nil, errors.New("no access token in refresh response")
	}

	newRefreshToken, _ := tokens["refresh_token"].(string)
	if newRefreshToken == "" {
		// Some servers may not issue new refresh token, reuse old one
		logger.Info("no new refresh token in response, reusing existing",
			"did", session.DID)
		newRefreshToken = session.RefreshToken
	}

	// Create updated session (preserving DID, DPoPKey, PDS)
	newSession := &Session{
		DID:          session.DID,
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
		DPoPKey:      session.DPoPKey,
		PDS:          session.PDS,
		DPoPNonce:    session.DPoPNonce, // Will be updated on next API call
	}

	// Parse new expiration times using internal helper
	if expiresAt, ok := oauth.ParseTokenExpiration(tokens, "expires_in"); ok {
		newSession.AccessTokenExpiresAt = expiresAt
		logger.Info("new access token expiration parsed",
			"expires_at", newSession.AccessTokenExpiresAt)
	}

	if refreshExpiresAt, ok := oauth.ParseTokenExpiration(tokens, "refresh_expires_in"); ok {
		newSession.RefreshTokenExpiresAt = refreshExpiresAt
		logger.Info("new refresh token expiration parsed",
			"refresh_expires_at", newSession.RefreshTokenExpiresAt)
	}

	logger.Info("token refresh successful",
		"did", session.DID,
		"new_access_token_expires_at", newSession.AccessTokenExpiresAt)

	// Audit: Token refresh success
	_ = LogAuditEvent(ctx, AuditEvent{
		EventType: AuditEventSessionRefresh,
		Actor:     session.DID,
		Action:    "refresh_access_token",
		Resource:  session.PDS,
		Result:    AuditResultSuccess,
	})

	return newSession, nil
}

// generateCodeVerifier generates a PKCE code verifier.
func generateCodeVerifier() string {
	return dpop.GenerateRandomString(64)
}

// generateCodeChallenge generates a PKCE code challenge from a verifier.
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
