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

- Uses PKCE (Proof Key for Code Exchange) for authorization
- Implements DPoP (Demonstrating Proof-of-Possession) for token binding
- Automatic nonce handling and retry logic
- Secure session ID generation

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
