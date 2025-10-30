# bskyoauth

**Do not use in _production_ without auditing by a human!**

A vibe-guided Go library for implementing Bluesky OAuth authentication with DPoP (Demonstrating Proof-of-Possession) support.

## Features

- Complete OAuth 2.0 authorization flow for Bluesky/AT Protocol
- DPoP token binding for enhanced security
- Automatic nonce handling and retry logic
- Flexible session storage interface
- Helper HTTP handlers for web applications
- Support for posting to Bluesky
- Clean, modular API design

## Installation

```bash
go get github.com/shindakun/bskyoauth
```

### Development Setup (Optional)

For contributors, install the pre-commit hooks for automatic security checks:

```bash
./scripts/install-hooks.sh
```

This installs a git hook that runs before each commit:
- `gofmt` - Code formatting check
- `golangci-lint` - Code quality and style (20+ linters)
- `govulncheck` - Vulnerability scanning
- `go test -race` - Tests with race detection
- `go mod verify` - Dependency verification

To bypass: `git commit --no-verify`

## Quick Start

### Basic Usage

```go
package main

import (
    "log"
    "net/http"

    "github.com/shindakun/bskyoauth"
)

func main() {
    // Create a new OAuth client
    client := bskyoauth.NewClient("http://localhost:8181")

    // Set up HTTP handlers
    http.HandleFunc("/client-metadata.json", client.ClientMetadataHandler())
    http.HandleFunc("/login", client.LoginHandler())
    http.HandleFunc("/callback", client.CallbackHandler(handleSuccess))

    log.Fatal(http.ListenAndServe(":8181", nil))
}

func handleSuccess(w http.ResponseWriter, r *http.Request, sessionID string) {
    // Set session cookie and redirect
    http.SetCookie(w, &http.Cookie{
        Name:     "session_id",
        Value:    sessionID,
        Path:     "/",
        HttpOnly: true,
    })
    http.Redirect(w, r, "/", http.StatusFound)
}
```

### Custom Configuration

```go
client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:      "https://myapp.com",
    ClientName:   "My Bluesky App",
    Scopes:       []string{"atproto", "transition:generic"},
    SessionStore: myCustomStore, // Implement bskyoauth.SessionStore interface
})
```

### Application Type

Configure the OAuth client application type based on your deployment:

```go
// Web application (default) - for web-based applications
client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:         "https://myapp.com",
    ApplicationType: bskyoauth.ApplicationTypeWeb, // or omit for default
})

// Native application - for desktop/mobile applications
client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:         "myapp://oauth",
    ApplicationType: bskyoauth.ApplicationTypeNative,
})
```

**Application Type Values:**
- `ApplicationTypeWeb` (`"web"`) - Default. For web-based applications
  - Must use HTTPS redirect URIs (except `localhost` for development)
  - Suitable for server-side web applications
- `ApplicationTypeNative` (`"native"`) - For native/desktop applications
  - May use custom URI schemes (e.g., `myapp://oauth`)
  - May use `http://localhost` redirect URIs
  - Suitable for desktop, mobile, or CLI applications

**Redirect URI Constraints:**

Web applications should use HTTPS redirect URIs:
```go
// ✓ Valid for web applications
https://myapp.com/callback
https://localhost:8181/callback  // OK for development

// ✗ Invalid for web applications
http://myapp.com/callback  // HTTP not allowed (except localhost)
myapp://callback          // Custom schemes not allowed
```

Native applications have more flexibility:
```go
// ✓ Valid for native applications
myapp://oauth/callback     // Custom URI scheme
http://localhost:8181      // Localhost with HTTP
http://127.0.0.1:8181      // Loopback with HTTP

// ✗ May be rejected by authorization servers
http://myapp.com/callback  // HTTP to non-localhost
```

The `application_type` is included in the OAuth client metadata and affects how the authorization server validates your redirect URIs according to [OpenID Connect Dynamic Client Registration](https://openid.net/specs/openid-connect-registration-1_0.html) and the [AT Protocol OAuth specification](https://atproto.com/specs/oauth).

### Manual OAuth Flow

For more control over the authentication flow:

```go
// Start the OAuth flow
flowState, err := client.StartAuthFlow(ctx, "user.bsky.social")
if err != nil {
    log.Fatal(err)
}

// Redirect user to flowState.AuthURL
// After callback with code, state, and issuer:

session, err := client.CompleteAuthFlow(ctx, code, state, issuer)
if err != nil {
    log.Fatal(err)
}

// Store the session
sessionID := bskyoauth.GenerateSessionID()
client.SessionStore.Set(sessionID, session)
```

### Creating Posts

```go
// Retrieve session
session, err := client.GetSession(sessionID)
if err != nil {
    log.Fatal(err)
}

// Create a post
err = client.CreatePost(ctx, session, "Hello from bskyoauth!")
if err != nil {
    log.Fatal(err)
}
```

## Custom Session Storage

Implement the `SessionStore` interface for custom storage backends:

```go
type SessionStore interface {
    Get(sessionID string) (*Session, error)
    Set(sessionID string, session *Session) error
    Delete(sessionID string) error
}
```

Example with Redis:

> **⚠️ Security Warning**: This example marshals the entire `Session` struct including the DPoP private key in plaintext. This is suitable for **development only**. For production deployments, see [DPoP Key Persistence and Security Considerations](#dpop-key-persistence-and-security-considerations) below for secure key handling.

```go
type RedisSessionStore struct {
    client *redis.Client
}

func (r *RedisSessionStore) Get(sessionID string) (*bskyoauth.Session, error) {
    data, err := r.client.Get(ctx, "session:"+sessionID).Bytes()
    if err != nil {
        return nil, err
    }

    var session bskyoauth.Session
    err = json.Unmarshal(data, &session)
    return &session, err
}

func (r *RedisSessionStore) Set(sessionID string, session *bskyoauth.Session) error {
    data, err := json.Marshal(session)
    if err != nil {
        return err
    }
    return r.client.Set(ctx, "session:"+sessionID, data, 24*time.Hour).Err()
}

func (r *RedisSessionStore) Delete(sessionID string) error {
    return r.client.Del(ctx, "session:"+sessionID).Err()
}
```

### Session Expiration and Cleanup

The built-in `MemorySessionStore` automatically expires sessions after **30 days** (matching cookie lifetime) and cleans them up every 5 minutes. This prevents:
- Memory leaks in long-running applications
- Extended exposure from stolen sessions
- Unbounded memory growth

**Custom Session Lifetime:**

```go
// 7-day sessions
store := bskyoauth.NewMemorySessionStoreWithTTL(
    7*24*time.Hour,  // TTL: 7 days
    1*time.Hour,     // Cleanup interval
)

client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:      "https://example.com",
    SessionStore: store,
})
```

**⚠️ Important: Synchronize Cookie and Session TTL**

When customizing session lifetime, ensure your cookie `MaxAge` matches:

```go
sessionTTL := 7 * 24 * time.Hour

// Configure session store
store := bskyoauth.NewMemorySessionStoreWithTTL(sessionTTL, 1*time.Hour)

// Configure cookie to match
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    MaxAge:   int(sessionTTL.Seconds()),  // Must match session TTL
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
})
```

**Graceful Shutdown:**

```go
defer store.Stop()  // Stop cleanup goroutine when shutting down
```

### DPoP Key Persistence and Security Considerations

The `Session` struct includes a `DPoPKey` field containing an ECDSA P-256 private key used for DPoP (Demonstrating Proof-of-Possession) token binding. By default, this key is **ephemeral** (exists only in memory) and is lost on application restart. **This is a security feature** that limits the blast radius if storage is compromised.

#### Security Trade-offs

| Approach | Security | User Experience | Use Case |
|----------|----------|-----------------|----------|
| **Ephemeral Keys** (Default) | ✅ High - keys never persisted | ⚠️ Users must re-authenticate after restart | Recommended for most applications |
| **Persisted Keys** | ⚠️ Lower - keys stored (encrypted) | ✅ Users stay logged in after restart | Long-running mobile/desktop apps |
| **Hybrid** | ✅ Good - keys temporary, tokens refreshed | ✅ Good - tokens extend sessions | **Recommended for production** |

#### Option 1: Ephemeral Keys (Default - Recommended)

With `MemorySessionStore`, DPoP keys are ephemeral:

```go
// Keys generated fresh for each OAuth flow
client := bskyoauth.NewClient("https://example.com")
flowState, _ := client.StartAuthFlow(ctx, handle)  // New DPoP key created
session, _ := client.CompleteAuthFlow(ctx, code, state, issuer)

// session.DPoPKey exists only in memory
// Lost on application restart
```

**Benefits:**
- ✅ Maximum security - keys can't be stolen from storage
- ✅ Automatic key rotation on each authentication
- ✅ Zero risk from compromised Redis/database
- ✅ Complies with OAuth 2.0 security best practices

**Drawback:**
- ⚠️ Users must re-authenticate after application restart

**Recommended for:**
- Web applications
- API services
- Short-lived sessions
- Security-critical applications

#### Option 2: Hybrid Approach (Recommended for Production)

Best of both worlds - keep keys ephemeral but extend sessions using token refresh:

```go
// Start with ephemeral key
session, _ := client.CompleteAuthFlow(ctx, code, state, issuer)

// Token refresh extends the session WITHOUT persisting keys
if session.IsAccessTokenExpired(5 * time.Minute) {
    newSession, err := client.RefreshToken(ctx, session)
    if err != nil {
        // Refresh failed - redirect to login
        http.Redirect(w, r, "/login", http.StatusFound)
        return
    }

    // newSession has SAME DPoPKey (still in memory only)
    client.UpdateSession(sessionID, newSession)
}
```

**Benefits:**
- ✅ Keys remain ephemeral (secure)
- ✅ Token refresh extends sessions (good UX)
- ✅ Re-authentication only needed after restart (acceptable)
- ✅ No encryption key management required

**This approach:**
- Keeps DPoP keys in memory only
- Uses OAuth token refresh to maintain sessions
- Only requires re-auth if application restarts (rare event)
- Provides good security AND user experience balance

**Recommended for:**
- Production web applications
- Applications with infrequent restarts
- Teams without encryption infrastructure

#### Option 3: Persisted Keys with Encryption (Advanced)

If you absolutely need keys to survive restarts (e.g., mobile apps), you **MUST** encrypt them:

```go
import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/x509"
    "encoding/json"
    "io"
)

type SecureRedisSessionStore struct {
    client *redis.Client
    gcm    cipher.AEAD  // AES-256-GCM cipher
}

func NewSecureRedisSessionStore(redisClient *redis.Client, encryptionKey []byte) (*SecureRedisSessionStore, error) {
    // encryptionKey must be 32 bytes (AES-256)
    block, err := aes.NewCipher(encryptionKey)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    return &SecureRedisSessionStore{
        client: redisClient,
        gcm:    gcm,
    }, nil
}

func (s *SecureRedisSessionStore) Set(sessionID string, session *bskyoauth.Session) error {
    // Serialize DPoP key to DER format
    keyBytes, err := x509.MarshalECPrivateKey(session.DPoPKey)
    if err != nil {
        return fmt.Errorf("failed to marshal key: %w", err)
    }

    // Generate random nonce
    nonce := make([]byte, s.gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return fmt.Errorf("failed to generate nonce: %w", err)
    }

    // Encrypt the key
    encryptedKey := s.gcm.Seal(nonce, nonce, keyBytes, nil)

    // Create storage-safe session struct (without private key)
    storageSession := struct {
        DID                  string    `json:"did"`
        AccessToken          string    `json:"access_token"`
        RefreshToken         string    `json:"refresh_token"`
        EncryptedDPoPKey     []byte    `json:"encrypted_dpop_key"`
        PDS                  string    `json:"pds"`
        DPoPNonce            string    `json:"dpop_nonce"`
        AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`
        RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
    }{
        DID:                   session.DID,
        AccessToken:           session.AccessToken,
        RefreshToken:          session.RefreshToken,
        EncryptedDPoPKey:      encryptedKey,
        PDS:                   session.PDS,
        DPoPNonce:             session.DPoPNonce,
        AccessTokenExpiresAt:  session.AccessTokenExpiresAt,
        RefreshTokenExpiresAt: session.RefreshTokenExpiresAt,
    }

    data, err := json.Marshal(storageSession)
    if err != nil {
        return fmt.Errorf("failed to marshal session: %w", err)
    }

    return s.client.Set(context.Background(), "session:"+sessionID, data, 24*time.Hour).Err()
}

func (s *SecureRedisSessionStore) Get(sessionID string) (*bskyoauth.Session, error) {
    data, err := s.client.Get(context.Background(), "session:"+sessionID).Bytes()
    if err != nil {
        return nil, err
    }

    var storageSession struct {
        DID                  string    `json:"did"`
        AccessToken          string    `json:"access_token"`
        RefreshToken         string    `json:"refresh_token"`
        EncryptedDPoPKey     []byte    `json:"encrypted_dpop_key"`
        PDS                  string    `json:"pds"`
        DPoPNonce            string    `json:"dpop_nonce"`
        AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`
        RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
    }

    if err := json.Unmarshal(data, &storageSession); err != nil {
        return nil, fmt.Errorf("failed to unmarshal session: %w", err)
    }

    // Decrypt the DPoP key
    if len(storageSession.EncryptedDPoPKey) < s.gcm.NonceSize() {
        return nil, fmt.Errorf("encrypted key too short")
    }

    nonce := storageSession.EncryptedDPoPKey[:s.gcm.NonceSize()]
    ciphertext := storageSession.EncryptedDPoPKey[s.gcm.NonceSize():]

    keyBytes, err := s.gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to decrypt key: %w", err)
    }

    // Parse the decrypted key
    dpopKey, err := x509.ParseECPrivateKey(keyBytes)
    if err != nil {
        return nil, fmt.Errorf("failed to parse key: %w", err)
    }

    return &bskyoauth.Session{
        DID:                   storageSession.DID,
        AccessToken:           storageSession.AccessToken,
        RefreshToken:          storageSession.RefreshToken,
        DPoPKey:               dpopKey,
        PDS:                   storageSession.PDS,
        DPoPNonce:             storageSession.DPoPNonce,
        AccessTokenExpiresAt:  storageSession.AccessTokenExpiresAt,
        RefreshTokenExpiresAt: storageSession.RefreshTokenExpiresAt,
    }, nil
}

func (s *SecureRedisSessionStore) Delete(sessionID string) error {
    return s.client.Del(context.Background(), "session:"+sessionID).Err()
}
```

**⚠️ Security Requirements for Persisted Keys:**

1. **Encryption**:
   - Use AES-256-GCM (or similar AEAD cipher)
   - Generate unique nonce for each encryption
   - Never reuse nonces

2. **Key Management**:
   - Store encryption key in secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)
   - **NEVER** commit encryption keys to version control
   - Rotate encryption keys periodically (e.g., every 90 days)
   - Use separate keys per environment (dev/staging/prod)

3. **Storage Security**:
   - Enable Redis encryption at rest
   - Use TLS for Redis connections
   - Restrict Redis network access (firewall rules)
   - Enable Redis AUTH

4. **Monitoring**:
   - Log encryption key access
   - Monitor for decryption failures (possible tampering)
   - Alert on unusual session access patterns

**Usage:**

```go
// Get encryption key from environment/secrets manager
encryptionKey := getEncryptionKeyFromSecretsManager()  // 32 bytes

store, err := NewSecureRedisSessionStore(redisClient, encryptionKey)
if err != nil {
    log.Fatal(err)
}

client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:      "https://example.com",
    SessionStore: store,
})
```

**Recommended for:**
- Mobile applications
- Desktop applications
- Applications with very infrequent deployment/restart

**NOT recommended for:**
- Web applications (use hybrid approach instead)
- Teams without encryption infrastructure
- Applications with frequent deployments

#### Key Rotation

DPoP keys are automatically rotated on each new authentication:
- New OAuth flow = new DPoP key
- Keys are bound to access token lifetime
- No manual rotation needed for ephemeral keys

For persisted keys, implement a rotation policy:
- Rotate encryption keys every 90 days
- Rotate on security events
- Force re-authentication periodically (e.g., every 30 days)

#### Summary Recommendations

| Scenario | Recommendation |
|----------|----------------|
| Web application | **Hybrid approach** - ephemeral keys + token refresh |
| API service | **Ephemeral keys** (default) |
| Mobile app | **Encrypted persistence** with secrets manager |
| Desktop app | **Encrypted persistence** with secure key storage |
| High security | **Ephemeral keys** - maximum security |
| Development | Simple Redis (from example above) is fine |

**Default behavior (ephemeral keys) is secure and recommended for most applications.**

## Logging

The library uses Go's standard `log/slog` for structured logging with environment-based configuration.

### Default Behavior

By default, the logger is **silent** (logs to `io.Discard`). No logging output unless explicitly configured.

### Automatic Environment-Based Configuration

The library automatically detects your environment and sets appropriate log levels:

```go
// Development (localhost) - Info level, text format
// Set BASE_URL=http://localhost:8181
logger := bskyoauth.NewLoggerFromEnv("http://localhost:8181")
bskyoauth.SetLogger(logger)

// Production - Error level, JSON format
// Set BASE_URL=https://myapp.com
logger := bskyoauth.NewLoggerFromEnv("https://myapp.com")
bskyoauth.SetLogger(logger)
```

### Manual Configuration

For full control over logging:

```go
// JSON logging at Error level
logger := bskyoauth.NewDefaultLogger(slog.LevelError)
bskyoauth.SetLogger(logger)

// Text logging at Debug level
logger := bskyoauth.NewTextLogger(slog.LevelDebug)
bskyoauth.SetLogger(logger)
```

### Context-Aware Logging

Add request and session IDs for request correlation:

```go
// In your HTTP handler
func handler(w http.ResponseWriter, r *http.Request) {
    // Generate request ID
    requestID := bskyoauth.GenerateRequestID()
    ctx := bskyoauth.WithRequestID(r.Context(), requestID)

    // Add session ID if available
    if sessionID, _ := r.Cookie("session_id"); sessionID != nil {
        ctx = bskyoauth.WithSessionID(ctx, sessionID.Value)
    }

    // Pass context to library methods
    session, err := client.CompleteAuthFlow(ctx, code, state, iss)
    // Logs will include request_id and session_id fields
}
```

### What Gets Logged

The library logs key security and operational events:

**OAuth Flow:**
- Auth flow initiation and completion
- Token exchange requests and responses
- DPoP nonce retries
- Security events (issuer mismatches, invalid states)

**Session Management:**
- Session creation, retrieval, and deletion
- Session expiration
- Periodic cleanup operations

**API Operations:**
- Post creation, record operations
- PDS endpoint lookups
- API request failures

**Rate Limiting:**
- Rate limit exceeded events
- Limiter cleanup operations

### Example Log Output

**Development (Text Format):**
```
time=2025-01-15T10:30:00.000-07:00 level=INFO msg="starting OAuth flow" handle=alice.bsky.social client_id=http://localhost:8181/client-metadata.json
time=2025-01-15T10:30:01.234-07:00 level=INFO msg="OAuth flow completed successfully" did=did:plc:abcd1234 issuer=https://bsky.social has_refresh_token=true
```

**Production (JSON Format):**
```json
{"time":"2025-01-15T17:30:00.000Z","level":"ERROR","msg":"SECURITY: issuer mismatch detected","expected_issuer":"https://bsky.social","received_issuer":"https://evil.com","did":"did:plc:abcd1234"}
```

### Security Logging

Critical security events are always logged at ERROR level:
- Issuer mismatch attacks
- Invalid OAuth states
- Token exchange failures
- Rate limit violations

## Token Refresh

Access tokens expire after a period of time (typically 1-2 hours). Use refresh tokens to obtain new access tokens without requiring the user to re-authenticate.

### Manual Token Refresh

```go
session, err := client.GetSession(sessionID)
if err != nil {
    log.Fatal(err)
}

// Check if token needs refresh (5 minute safety buffer)
if session.IsAccessTokenExpired(5 * time.Minute) {
    newSession, err := client.RefreshToken(ctx, session)
    if err != nil {
        // Refresh failed - user needs to re-authenticate
        return redirectToLogin(w, r)
    }

    // Update session in store
    err = client.UpdateSession(sessionID, newSession)
    if err != nil {
        log.Fatal(err)
    }

    session = newSession
}

// Use refreshed session for API calls
err = client.CreatePost(ctx, session, "Hello from refreshed token!")
```

### Token Expiration Checking

Check token status before making API calls:

```go
// Check if access token is expired or will expire soon
if session.IsAccessTokenExpired(5 * time.Minute) {
    // Token needs refresh
}

// Check if refresh token is expired
if session.IsRefreshTokenExpired() {
    // Need full re-authentication - redirect to login
}

// Get time remaining until expiration
remaining := session.TimeUntilAccessTokenExpiry()
log.Printf("Token expires in: %v", remaining)
```

### Error Handling

Refresh tokens can expire or become invalid. Handle refresh failures gracefully:

```go
newSession, err := client.RefreshToken(ctx, session)
if err != nil {
    // Common reasons for failure:
    // - Refresh token expired
    // - Refresh token revoked
    // - Network error
    // - PDS unavailable

    // User needs to re-authenticate
    log.Printf("Token refresh failed: %v", err)
    return redirectToLogin(w, r)
}

// Success - update session
client.UpdateSession(sessionID, newSession)
```

### Handling Expired Tokens in API Calls

While proactive token refresh (checking expiration before API calls) is recommended, you should also handle expired tokens reactively by catching 401 errors:

```go
// Attempt API operation
err := client.CreatePost(ctx, session, "Hello!")
if err != nil {
    // Check if error is due to expired token
    if strings.Contains(err.Error(), "invalid_token") && strings.Contains(err.Error(), "401") {
        log.Printf("Token expired during API call, attempting refresh")

        // Refresh the token
        newSession, refreshErr := client.RefreshToken(ctx, session)
        if refreshErr != nil {
            log.Printf("Token refresh failed: %v", refreshErr)
            return errors.New("session expired, please log in again")
        }

        // Update session in your store
        if err := updateSessionInStore(sessionID, newSession); err != nil {
            return fmt.Errorf("failed to update session: %w", err)
        }

        // Retry the operation with refreshed token
        if err := client.CreatePost(ctx, newSession, "Hello!"); err != nil {
            return fmt.Errorf("operation failed after refresh: %w", err)
        }

        log.Printf("Successfully retried operation after token refresh")
        return nil
    }

    // Other errors - return as-is
    return err
}
```

This pattern handles cases where:
- Tokens expire between the expiration check and the API call
- Users return after long periods of inactivity (12+ hours)
- Clock skew causes premature expiration

### Important Notes

- **Single-Use Tokens**: Per AT Protocol spec, refresh tokens are single-use. The old refresh token becomes invalid after a successful refresh.
- **DPoP Binding**: Token refresh maintains the same DPoP key binding as the original authentication.
- **Automatic Expiration**: The library tracks token expiration times when available from the server.
- **No Expiration Data**: If the server doesn't provide expiration times, the helper methods assume tokens are valid.

## Timeout Configuration

The library uses sensible default timeouts for all HTTP operations to prevent requests from hanging indefinitely.

### Default Timeouts

- **Request Timeout**: 30 seconds (total request time)
- **Connection Timeout**: 10 seconds (TCP handshake)
- **TLS Handshake**: 10 seconds
- **Response Headers**: 10 seconds
- **Idle Connections**: Reused for 90 seconds

### Custom Timeouts

Configure custom timeouts for specific requirements:

```go
// Custom HTTP client with shorter timeout
customClient := &http.Client{
    Timeout: 10 * time.Second,
}

client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:    "https://myapp.com",
    HTTPClient: customClient,
})
```

### Context Timeouts

Use context timeouts for per-request control:

```go
// 5 second timeout for this specific request
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()

flowState, err := client.StartAuthFlow(ctx, handle)
if err != nil {
    if errors.Is(err, context.DeadlineExceeded) {
        log.Println("Request timed out")
    }
}
```

### Testing with Timeouts

Override the HTTP client for testing:

```go
// Fast timeout for tests
testClient := &http.Client{Timeout: 1 * time.Second}
bskyoauth.SetHTTPClient(testClient)
defer bskyoauth.SetHTTPClient(bskyoauth.GetHTTPClient())
```

### Timeout Error Detection

The library provides a helper to detect timeout errors:

```go
_, err := client.StartAuthFlow(ctx, handle)
if err != nil {
    if bskyoauth.IsTimeoutError(err) {
        log.Println("Request timed out - check network connection")
    } else {
        log.Printf("Other error: %v", err)
    }
}
```

## Example Application

A complete web application example is available in [examples/web-demo](examples/web-demo/main.go).

To run the example:

```bash
cd examples/web-demo
go run main.go
```

Then visit http://localhost:8181 and log in with your Bluesky handle. (You'll probably want to use the Ngrok example below instead.)

## Architecture

The library is organized into several modules:

- **client.go** - Main API and high-level operations
- **oauth.go** - OAuth authorization flow implementation
- **dpop.go** - DPoP proof generation and HTTP transport
- **session.go** - Session management utilities
- **types.go** - Core data types and interfaces

## Security

### ⚠️ HTTPS Required for Production

**CRITICAL: This library MUST be used with HTTPS in production environments.**

OAuth 2.0 authorization flows transmit sensitive data including:
- Authorization codes
- State parameters
- Session cookies
- Access tokens

**Running OAuth over HTTP exposes these credentials to interception and compromise.**

For local development on `localhost`, HTTP is acceptable. For any production or publicly accessible deployment, HTTPS is mandatory.

### Security Features

- Uses PKCE (Proof Key for Code Exchange) for authorization
- Implements DPoP (Demonstrating Proof-of-Possession) for token binding
- Automatic nonce handling and retry logic
- Secure session ID generation (cryptographically random)
- OAuth state expiration (10-minute TTL) with automatic cleanup
- Issuer validation to prevent authorization code injection attacks
- Comprehensive input validation to prevent injection attacks and resource exhaustion

### Input Validation

The library performs comprehensive input validation to prevent errors and security issues:

- **Handles**: Validated against AT Protocol handle specification
  - Maximum 253 characters total
  - Each segment maximum 63 characters
  - Only lowercase letters, digits, and hyphens allowed
  - Proper format enforcement (no trailing dots, TLD cannot start with digit)

- **Post Text**: Limited to 300 characters per AT Protocol spec
  - UTF-8 validation
  - Null byte rejection
  - Whitespace-only text rejection

- **Custom Records**: Field-level validation with configurable limits
  - Text field validation up to 1000 characters (configurable)
  - DateTime format validation
  - Deep nesting prevention (max 10 levels)

- **Collection Names**: Must be valid NSIDs (e.g., "app.bsky.feed.post")

All validation errors return descriptive error messages for debugging.

#### Using Validation Functions

Validation functions are exported and can be called directly:

```go
// Validate a handle
if err := bskyoauth.ValidateHandle("alice.bsky.social"); err != nil {
    log.Printf("Invalid handle: %v", err)
}

// Validate post text
if err := bskyoauth.ValidatePostText("Hello, world!"); err != nil {
    log.Printf("Invalid post text: %v", err)
}

// Validate a custom text field with custom limit
if err := bskyoauth.ValidateTextField(description, "description", 500); err != nil {
    log.Printf("Invalid field: %v", err)
}

// Validate record fields
record := map[string]interface{}{
    "text":      "My post",
    "createdAt": "2025-01-15T12:00:00.000Z",
}
if err := bskyoauth.ValidateRecordFields(record); err != nil {
    log.Printf("Invalid record: %v", err)
}

// Validate collection NSID
if err := bskyoauth.ValidateCollectionNSID("app.bsky.feed.post"); err != nil {
    log.Printf("Invalid collection: %v", err)
}
```

### Security Headers

The library includes automatic security headers middleware with built-in support for Bluesky API integration.

**Basic Usage (includes Bluesky domains automatically):**

```go
mux := http.NewServeMux()
// ... set up handlers ...
handler := bskyoauth.SecurityHeadersMiddleware()(mux)
http.ListenAndServe(":8080", handler)
```

**Custom Options:**

```go
opts := &bskyoauth.SecurityHeadersOptions{
    // Add additional API domains
    CSPConnectSrc: []string{
        "'self'",
        "https://*.bsky.social",      // Already included by default
        "https://api.myservice.com",  // Custom domain
    },

    // Add custom headers
    CustomHeaders: map[string]string{
        "X-Custom-Header": "value",
    },

    // Add additional CSP directives
    AdditionalCSPDirectives: map[string][]string{
        "media-src":  {"'self'", "https://cdn.example.com"},
        "worker-src": {"'self'"},
    },
}

handler := bskyoauth.SecurityHeadersMiddlewareWithOptions(opts)(mux)
http.ListenAndServe(":8080", handler)
```

**Default CSP Policies:**

**Localhost:**
- `default-src 'self'`
- `script-src 'self' 'unsafe-inline' 'unsafe-eval'` (for hot-reload)
- `style-src 'self' 'unsafe-inline'`
- `img-src 'self' data:`
- `connect-src 'self' https://*.bsky.social https://bsky.social`
- `form-action 'self' https://*.bsky.social https://bsky.social`

**Production:**
- `default-src 'self'`
- `script-src 'self'` (strict - no unsafe directives)
- `style-src 'self'`
- `img-src 'self' data:`
- `connect-src 'self' https://*.bsky.social https://bsky.social`
- `form-action 'self' https://*.bsky.social https://bsky.social`
- `frame-ancestors 'none'`
- `base-uri 'self'`

**Bluesky Integration:**

The default CSP automatically includes Bluesky domains in both `connect-src` and `form-action`, allowing:
- HTML forms to POST directly to Bluesky API endpoints
- Client-side JavaScript API calls to Bluesky servers
- Wildcard `*.bsky.social` supports user-specific PDS domains

**Note:** Server-side Go HTTP requests (current implementation) are NOT affected by CSP. The CSP enables browser-based form submissions and API calls to Bluesky.

**Headers Applied:**
- **Content-Security-Policy**: Environment-aware (relaxed for localhost, strict for production)
- **X-Frame-Options**: DENY (prevents clickjacking)
- **X-Content-Type-Options**: nosniff (prevents MIME-sniffing attacks)
- **Strict-Transport-Security**: HTTPS production only (not localhost)
- **X-XSS-Protection**: 1; mode=block
- **Referrer-Policy**: strict-origin-when-cross-origin

**How it Works:**

The middleware automatically detects localhost from the HTTP request's `Host` header:
- Localhost addresses: `localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`
- Production: Everything else

HTTPS detection checks:
- `r.TLS != nil` (direct HTTPS connection)
- `X-Forwarded-Proto: https` (reverse proxy)

No configuration needed - the middleware works automatically in any deployment scenario, including reverse proxies, Docker, and cloud platforms.

### Access Token Handling

Per the [AT Protocol OAuth specification](https://atproto.com/specs/oauth), **access tokens are opaque from the client's perspective**. This library follows the spec:

- **Tokens are treated as opaque strings** - no client-side signature validation is performed
- **Server-side validation**: The PDS (Resource Server) validates tokens when they're used
- **DPoP binding**: All tokens are bound to unique session keys via DPoP proofs
- **Automatic expiration**: Tokens include expiration times enforced by the server

While tokens may be JWTs internally, the library does not validate signatures or claims. This is intentional and follows the AT Protocol design where:

1. Token validation is the responsibility of the Resource Server (PDS)
2. DPoP provides proof-of-possession security
3. Tokens are bound to specific client instances and cannot be reused

The library parses JWTs only to extract the user's DID for session management, but treats the token as opaque for all other purposes.

### Production Deployment Best Practices

#### 1. Always Use HTTPS
- Use TLS 1.2 or higher
- Obtain certificates from a trusted CA (Let's Encrypt is free)
- Use a reverse proxy (nginx, Caddy, Traefik) for TLS termination

#### 2. Cookie Security
Configure secure session cookies in production:
```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    Path:     "/",
    HttpOnly: true,           // Prevents JavaScript access
    Secure:   true,           // HTTPS only - REQUIRED in production
    SameSite: http.SameSiteLaxMode, // CSRF protection
    MaxAge:   86400,          // 24 hours (adjust as needed)
})
```

#### 3. Session Storage
- Use persistent session storage (Redis, database) instead of in-memory store
- Implement session expiration and cleanup
- Consider encrypted storage for sensitive session data

#### 4. Rate Limiting
Implement rate limiting on sensitive endpoints:
- `/login` - Prevent brute force attacks
- `/callback` - Prevent token exchange attacks
- API endpoints - Prevent abuse

#### 5. Environment Configuration
```bash
# Production
BASE_URL=https://yourdomain.com

# Development
BASE_URL=http://localhost:8181
```

#### 6. Reverse Proxy Configuration

**Nginx Example:**
```nginx
server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://localhost:8181;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**Caddy Example (automatic HTTPS):**
```
yourdomain.com {
    reverse_proxy localhost:8181
}
```

**ngrok Example (development/testing with HTTPS):**

[ngrok](https://ngrok.com/) provides a quick way to expose your local development server with HTTPS, perfect for testing OAuth flows. Thanks ngrok! :D

```bash
# Install ngrok (if not already installed)
# Visit https://ngrok.com/ to sign up and get your auth token

# Start your application on port 8181
cd examples/web-demo
BASE_URL=https://YOUR_SUBDOMAIN.ngrok.app go run main.go

# In another terminal, start ngrok
ngrok http 8181

# ngrok will display a URL like: https://abc123.ngrok.app
# Update your BASE_URL environment variable to match:
BASE_URL=https://abc123.ngrok.app go run main.go
```

**ngrok Features:**
- ✓ Automatic HTTPS with valid certificates
- ✓ Inspect HTTP requests in web interface (http://127.0.0.1:4040)
- ✓ No server configuration required
- ✓ Perfect for development and testing OAuth flows
- ✓ Works with Bluesky's OAuth redirect requirements

**Note:** ngrok URLs change on each restart with the free tier. For a permanent subdomain, upgrade to a paid plan or use a reverse proxy in production.

#### 7. Additional Security Measures
- Keep dependencies updated (`go get -u ./...`)
- Monitor for security advisories
- Implement logging for security events
- Use environment variables for sensitive configuration
- Never commit credentials or secrets to version control

### Security Checklist for Production

- [ ] Application served over HTTPS
- [ ] TLS certificates valid and from trusted CA
- [ ] Cookie `Secure` flag enabled
- [ ] Cookie `HttpOnly` flag enabled
- [ ] Cookie `SameSite` attribute set
- [ ] Session expiration configured
- [ ] Persistent session storage implemented
- [ ] Rate limiting enabled
- [ ] Security headers configured (CSP, HSTS, etc.)
- [ ] Dependencies up to date
- [ ] Logging and monitoring enabled
- [ ] Secrets stored in environment variables or secret manager

## Requirements

- Go 1.21 or later
- Valid Bluesky/AT Protocol account for testing

## Environment Variables

The example application supports:

- `BASE_URL` - Base URL for OAuth client (default: `http://localhost:8181`)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

This project is provided as-is for educational and development purposes.

## See Also

- [Bluesky AT Protocol Documentation](https://atproto.com/)
- [OAuth 2.0 DPoP Specification](https://datatracker.ietf.org/doc/html/rfc9449)
- [PKCE Specification](https://datatracker.ietf.org/doc/html/rfc7636)
