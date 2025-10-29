# Implementation Plan: Refresh Token Support (Issue #12)

## Overview

Implement token refresh functionality to allow access token renewal without requiring full re-authentication. This improves user experience and enables shorter-lived access tokens for better security.

## Current State

**What We Have:**
- ✅ Refresh tokens are received and stored in `Session` struct
- ✅ DPoP key binding is already implemented
- ✅ Token endpoint discovery via authorization server metadata
- ✅ Session storage infrastructure exists

**What's Missing:**
- ❌ No `RefreshToken()` method to perform refresh
- ❌ No automatic refresh before token expiration
- ❌ No token expiration tracking
- ❌ No graceful handling of refresh token expiration

## AT Protocol Requirements

Per [AT Protocol OAuth Spec](https://atproto.com/specs/oauth):

1. **Single-Use Refresh Tokens**: "Refresh tokens are generally single-use, with the 'new' refresh token replacing that used in the token request"
2. **DPoP Binding**: "Tokens (both access and refresh) are always bound to a unique session DPoP key"
3. **Grant Type**: Must include `refresh_token` in client metadata `grant_types`
4. **Lifetime Limits**:
   - Public clients: 2 weeks per refresh token
   - Confidential clients: 180 days per refresh token

## Implementation Plan

### Phase 1: Core Refresh Token Functionality

#### 1.1 Add Token Expiration Tracking

**File:** `types.go`

Add fields to `Session`:
```go
type Session struct {
    DID          string
    AccessToken  string
    RefreshToken string
    DPoPKey      *ecdsa.PrivateKey
    PDS          string
    DPoPNonce    string

    // NEW: Token expiration tracking
    AccessTokenExpiresAt  time.Time  // When access token expires
    RefreshTokenExpiresAt time.Time  // When refresh token expires (optional)
}
```

**Why:** Need to know when tokens expire to trigger refresh

#### 1.2 Parse Token Expiration from Response

**File:** `oauth.go` - Modify `CompleteAuthFlow()`

Update token response parsing:
```go
// After token exchange, parse expiration
if expiresIn, ok := tokens["expires_in"].(float64); ok {
    session.AccessTokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
}

// Optional: Parse refresh token expiration if provided
if refreshExpiresIn, ok := tokens["refresh_expires_in"].(float64); ok {
    session.RefreshTokenExpiresAt = time.Now().Add(time.Duration(refreshExpiresIn) * time.Second)
}
```

#### 1.3 Implement RefreshToken Method

**File:** `oauth.go`

Add new method:
```go
// RefreshToken exchanges a refresh token for new access and refresh tokens.
// Per AT Protocol spec, refresh tokens are single-use - the old refresh token
// becomes invalid after a successful refresh.
func (c *Client) RefreshToken(ctx context.Context, session *Session) (*Session, error) {
    logger := LoggerFromContext(ctx)
    logger.Info("refreshing access token",
        "did", session.DID)

    // Validate we have a refresh token
    if session.RefreshToken == "" {
        return nil, errors.New("no refresh token available")
    }

    // Check if refresh token is expired
    if !session.RefreshTokenExpiresAt.IsZero() && time.Now().After(session.RefreshTokenExpiresAt) {
        logger.Warn("refresh token expired",
            "did", session.DID,
            "expired_at", session.RefreshTokenExpiresAt)
        return nil, errors.New("refresh token expired")
    }

    // Get token endpoint from PDS
    metadataURL := session.PDS + "/.well-known/oauth-authorization-server"
    resp, err := http.Get(metadataURL)
    if err != nil {
        logger.Error("failed to get auth server metadata for refresh",
            "pds", session.PDS,
            "error", err)
        return nil, fmt.Errorf("failed to get auth server metadata: %w", err)
    }
    defer resp.Body.Close()

    var metadata AuthServerMetadata
    if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
        return nil, fmt.Errorf("failed to decode metadata: %w", err)
    }

    // Perform refresh token request with DPoP
    tokens, err := c.refreshTokenRequest(ctx, metadata.TokenEndpoint, session.RefreshToken, session.DPoPKey, session.DPoPNonce)
    if err != nil {
        logger.Error("token refresh failed",
            "did", session.DID,
            "error", err)
        return nil, fmt.Errorf("token refresh failed: %w", err)
    }

    // Extract new tokens
    newAccessToken, ok := tokens["access_token"].(string)
    if !ok || newAccessToken == "" {
        return nil, errors.New("no access token in refresh response")
    }

    newRefreshToken, _ := tokens["refresh_token"].(string)
    if newRefreshToken == "" {
        // Some servers may not issue new refresh token
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

    // Parse new expiration times
    if expiresIn, ok := tokens["expires_in"].(float64); ok {
        newSession.AccessTokenExpiresAt = time.Now().Add(time.Duration(expiresIn) * time.Second)
    }

    if refreshExpiresIn, ok := tokens["refresh_expires_in"].(float64); ok {
        newSession.RefreshTokenExpiresAt = time.Now().Add(time.Duration(refreshExpiresIn) * time.Second)
    }

    logger.Info("token refresh successful",
        "did", session.DID,
        "new_access_token_expires_at", newSession.AccessTokenExpiresAt)

    return newSession, nil
}
```

#### 1.4 Implement refreshTokenRequest Helper

**File:** `oauth.go`

Add helper method:
```go
// refreshTokenRequest performs the refresh token exchange with DPoP
func (c *Client) refreshTokenRequest(ctx context.Context, tokenEndpoint, refreshToken string, dpopKey interface{}, currentNonce string) (map[string]interface{}, error) {
    logger := LoggerFromContext(ctx)

    // Create DPoP proof for refresh request
    dpopProof, err := createDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", currentNonce)
    if err != nil {
        return nil, err
    }

    // Build refresh token request
    data := url.Values{}
    data.Set("grant_type", "refresh_token")
    data.Set("refresh_token", refreshToken)
    data.Set("client_id", c.ClientID)

    req, _ := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("DPoP", dpopProof)

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, _ := io.ReadAll(resp.Body)

    // Handle DPoP nonce retry (same as token exchange)
    if resp.StatusCode == http.StatusBadRequest {
        var errorResp map[string]interface{}
        if err := json.Unmarshal(body, &errorResp); err == nil {
            if errorResp["error"] == "use_dpop_nonce" {
                nonce := resp.Header.Get("DPoP-Nonce")
                if nonce != "" {
                    logger.Info("retrying token refresh with DPoP nonce",
                        "token_endpoint", tokenEndpoint)

                    // Retry with nonce
                    dpopProof, err = createDPoPProof(dpopKey.(*ecdsa.PrivateKey), "POST", tokenEndpoint, "", nonce)
                    if err != nil {
                        return nil, err
                    }

                    req, _ = http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
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
        logger.Error("token refresh request failed",
            "token_endpoint", tokenEndpoint,
            "status", resp.Status,
            "body", string(body))
        return nil, fmt.Errorf("token refresh failed (status: %d)", resp.StatusCode)
    }

    var tokens map[string]interface{}
    if err := json.Unmarshal(body, &tokens); err != nil {
        return nil, err
    }

    return tokens, nil
}
```

#### 1.5 Update Client Metadata

**File:** `client.go` - Modify `GetClientMetadata()`

Add `refresh_token` to grant types:
```go
func (c *Client) GetClientMetadata() map[string]interface{} {
    return map[string]interface{}{
        "client_id":                  c.ClientID,
        "client_name":                c.ClientName,
        "redirect_uris":              []string{c.RedirectURI},
        "scope":                      "atproto transition:generic",
        "grant_types":                []string{"authorization_code", "refresh_token"}, // Added refresh_token
        "response_types":             []string{"code"},
        "token_endpoint_auth_method": "none",
        "application_type":           "web",
        "dpop_bound_access_tokens":   true,
    }
}
```

### Phase 2: Helper Methods & Utilities

#### 2.1 Add Token Expiration Checking

**File:** `client.go` or new `token.go`

Add helper methods:
```go
// IsAccessTokenExpired checks if the access token has expired or will expire soon.
// The buffer parameter adds a safety margin (e.g., 5 minutes) to refresh before actual expiration.
func (s *Session) IsAccessTokenExpired(buffer time.Duration) bool {
    if s.AccessTokenExpiresAt.IsZero() {
        return false // No expiration info, assume valid
    }
    return time.Now().Add(buffer).After(s.AccessTokenExpiresAt)
}

// IsRefreshTokenExpired checks if the refresh token has expired.
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
```

#### 2.2 Add Session Update Helper

**File:** `client.go`

Add method to update session in store:
```go
// UpdateSession updates an existing session with new tokens after refresh.
func (c *Client) UpdateSession(sessionID string, newSession *Session) error {
    // Delete old session
    if err := c.SessionStore.Delete(sessionID); err != nil {
        return err
    }
    // Store updated session
    return c.SessionStore.Set(sessionID, newSession)
}
```

### Phase 3: Automatic Refresh (Optional - Advanced)

#### 3.1 Add Automatic Refresh to API Methods

**File:** `client.go`

Modify API methods to check token expiration:
```go
// CreatePost with automatic token refresh
func (c *Client) CreatePost(ctx context.Context, sessionID string, text string) error {
    session, err := c.GetSession(sessionID)
    if err != nil {
        return err
    }

    // Check if token needs refresh (5 minute buffer)
    if session.IsAccessTokenExpired(5 * time.Minute) {
        logger := LoggerFromContext(ctx)
        logger.Info("access token expired, attempting refresh",
            "session_id", sessionID,
            "did", session.DID)

        // Attempt refresh
        newSession, err := c.RefreshToken(ctx, session)
        if err != nil {
            logger.Error("automatic token refresh failed",
                "session_id", sessionID,
                "did", session.DID,
                "error", err)
            return fmt.Errorf("token refresh failed: %w", err)
        }

        // Update session in store
        if err := c.UpdateSession(sessionID, newSession); err != nil {
            return err
        }

        session = newSession
        logger.Info("automatic token refresh successful",
            "session_id", sessionID,
            "did", session.DID)
    }

    // Proceed with original CreatePost logic...
}
```

**Note:** This adds complexity. Consider making it opt-in via configuration.

### Phase 4: Testing

#### 4.1 Unit Tests

**File:** `oauth_test.go`

Add tests for:
```go
// Test successful refresh
func TestRefreshToken(t *testing.T)

// Test refresh with expired refresh token
func TestRefreshTokenExpired(t *testing.T)

// Test refresh with missing refresh token
func TestRefreshTokenMissing(t *testing.T)

// Test refresh with DPoP nonce retry
func TestRefreshTokenDPoPNonceRetry(t *testing.T)

// Test token expiration helpers
func TestIsAccessTokenExpired(t *testing.T)
func TestIsRefreshTokenExpired(t *testing.T)
func TestTimeUntilAccessTokenExpiry(t *testing.T)
```

#### 4.2 Integration Tests

Consider adding integration tests with mock OAuth server that:
- Issues tokens with short expiration
- Validates refresh token usage
- Tests single-use refresh token behavior

### Phase 5: Documentation

#### 5.1 Update README.md

Add section on token refresh:
```markdown
## Token Refresh

Access tokens expire after a period of time. Use refresh tokens to obtain new access tokens without re-authentication:

### Manual Refresh

```go
session, err := client.GetSession(sessionID)
if err != nil {
    log.Fatal(err)
}

// Check if token needs refresh
if session.IsAccessTokenExpired(5 * time.Minute) {
    newSession, err := client.RefreshToken(ctx, session)
    if err != nil {
        // Refresh failed - may need to re-authenticate
        log.Fatal(err)
    }

    // Update session in store
    client.UpdateSession(sessionID, newSession)
    session = newSession
}

// Use refreshed session
client.CreatePost(ctx, session, "Hello!")
```

### Automatic Refresh (if implemented)

When enabled, API methods automatically refresh expired tokens:
```go
// Token refresh happens automatically if needed
err := client.CreatePost(ctx, sessionID, "Hello!")
```

### Token Expiration

Check token status:
```go
// Check if access token is expired or will expire in 5 minutes
if session.IsAccessTokenExpired(5 * time.Minute) {
    // Needs refresh
}

// Check if refresh token is expired
if session.IsRefreshTokenExpired() {
    // Need full re-authentication
}

// Get time until expiration
remaining := session.TimeUntilAccessTokenExpiry()
log.Printf("Token expires in: %v", remaining)
```

### Error Handling

Refresh tokens can expire or become invalid:
```go
newSession, err := client.RefreshToken(ctx, session)
if err != nil {
    // Refresh failed - user needs to re-authenticate
    // Redirect to login flow
    return redirectToLogin(w, r)
}
```
```

#### 5.2 Update CHANGELOG.md

Add to Unreleased section:
```markdown
### Added
- **Token Refresh Support**: Implemented refresh token functionality (Issue #12)
  - Added `RefreshToken()` method to exchange refresh tokens for new access tokens
  - Added token expiration tracking to `Session` struct
  - Added helper methods: `IsAccessTokenExpired()`, `IsRefreshTokenExpired()`, `TimeUntilAccessTokenExpiry()`
  - Added `UpdateSession()` method to update sessions after refresh
  - Updated client metadata to include `refresh_token` grant type
  - DPoP binding maintained across token refresh
  - Comprehensive logging for refresh operations
  - Per AT Protocol spec: single-use refresh tokens, DPoP proof required
  - [Optional] Automatic token refresh in API methods
```

## Implementation Strategy

### Recommended Approach

1. **Start with Phase 1** (Core Functionality)
   - Implement basic `RefreshToken()` method
   - Add expiration tracking
   - Update client metadata
   - Test manually with web-demo

2. **Add Phase 2** (Helpers)
   - Token expiration checking
   - Session update method
   - Makes refresh easier to use

3. **Consider Phase 3** (Automatic Refresh)
   - Only if user experience requires it
   - Adds complexity, may not be needed
   - Alternative: Let applications handle refresh timing

4. **Complete Phase 4 & 5** (Testing & Docs)
   - Comprehensive tests
   - Clear documentation
   - Usage examples

### Breaking Changes

**None** - All additions are backwards compatible:
- New fields in `Session` with zero values are safe
- New methods don't affect existing code
- Client metadata update is compatible

### Considerations

1. **Single-Use Tokens**: Refresh tokens are invalidated after use. Need to update session immediately.
2. **Concurrent Requests**: Multiple simultaneous refreshes could cause issues. Consider adding mutex if automatic refresh is implemented.
3. **Error Handling**: Failed refresh should prompt re-authentication, not silent retry loops.
4. **Token Lifetime**: Access tokens typically expire in 1-2 hours. Refresh tokens in days/weeks.
5. **DPoP Key Binding**: Same DPoP key used for refresh as initial auth. Key rotation not supported in current implementation.

## Success Criteria

- ✅ Manual token refresh works with `RefreshToken()` method
- ✅ Token expiration is tracked and queryable
- ✅ DPoP proofs work with refresh requests
- ✅ Session updates preserve all fields correctly
- ✅ Comprehensive test coverage
- ✅ Documentation with clear examples
- ✅ No breaking changes to existing API

## Timeline Estimate

- Phase 1 (Core): 2-3 hours
- Phase 2 (Helpers): 1 hour
- Phase 3 (Automatic): 2-3 hours (if implemented)
- Phase 4 (Testing): 2-3 hours
- Phase 5 (Documentation): 1 hour

**Total**: ~8-13 hours depending on scope

## References

- [AT Protocol OAuth Specification](https://atproto.com/specs/oauth)
- [RFC 6749 - OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749#section-6)
- [RFC 9449 - OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/rfc9449)
