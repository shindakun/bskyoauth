# bskyoauth

A Go library for implementing Bluesky OAuth authentication with DPoP (Demonstrating Proof-of-Possession) support.

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

## Example Application

A complete web application example is available in [examples/web-demo](examples/web-demo/main.go).

To run the example:

```bash
cd examples/web-demo
go run main.go
```

Then visit http://localhost:8181 and log in with your Bluesky handle.

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
