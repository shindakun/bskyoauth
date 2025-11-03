# Bluesky Chat OAuth Demo

This example demonstrates how to use the bskyoauth library with additional OAuth scopes, specifically the `transition:chat.bsky` scope. It shows how to:

1. Request multiple OAuth scopes including the chat scope
2. Use XRPC to call Bluesky APIs directly
3. Fetch and display user profile information using `app.bsky.actor.getProfile`

## Features

- **Extended OAuth Scopes**: Requests `atproto`, `transition:generic`, and `transition:chat.bsky` scopes
- **XRPC Integration**: Direct XRPC calls to fetch user profile data
- **Profile Display**: Shows user avatar, display name, handle, bio, and stats (followers, following, posts)
- **DPoP Authentication**: Properly handles DPoP tokens for authenticated requests
- **Token Refresh**: Automatic token refresh when tokens expire

## Configuration

The demo uses the following environment variables:

- `BASE_URL`: Base URL for the OAuth client (default: `http://localhost:8182`)
- `SERVER_PORT`: Port to run the server on (default: `8182`)
- `SESSION_TIMEOUT_DAYS`: Session timeout in days (default: `30`)
- `RATE_LIMIT_AUTH`: Auth endpoint rate limit in "req/sec,burst" format (default: `5,10`)
- `RATE_LIMIT_API`: API endpoint rate limit in "req/sec,burst" format (default: `10,20`)

## Running the Demo

1. Start the server:

```bash
cd examples/web-demo-chat
go run main.go
```

2. Open your browser to `http://localhost:8182`

3. Log in with your Bluesky handle (e.g., `yourname.bsky.social`)

4. After authentication, click "View My Profile (XRPC)" to see your profile fetched via XRPC

## How It Works

### Custom Scopes

The demo creates a client with custom scopes:

```go
client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:    baseURL,
    HTTPClient: httpClient,
    Scopes:     []string{"atproto", "transition:generic", "transition:chat.bsky"},
})
```

### XRPC Profile Fetch

The `getProfile` function demonstrates direct XRPC usage:

```go
func getProfile(ctx context.Context, session *bskyoauth.Session) (*bsky.ActorDefs_ProfileViewDetailed, error) {
    // Resolve PDS endpoint for the user
    dir := identity.DefaultDirectory()
    atid, err := syntax.ParseAtIdentifier(session.DID)
    if err != nil {
        return nil, fmt.Errorf("failed to parse DID: %w", err)
    }

    ident, err := dir.Lookup(ctx, *atid)
    if err != nil {
        return nil, fmt.Errorf("failed to lookup identity: %w", err)
    }

    pdsHost := ident.PDSEndpoint()

    // Create DPoP transport for authenticated requests
    transport := bskyoauth.NewDPoPTransport(
        http.DefaultTransport,
        session.DPoPKey,
        session.AccessToken,
        session.DPoPNonce,
    )

    httpClient := &http.Client{
        Transport: transport,
    }

    xrpcClient := &xrpc.Client{
        Host:   pdsHost,
        Client: httpClient,
    }

    // Call app.bsky.actor.getProfile
    output, err := bsky.ActorGetProfile(ctx, xrpcClient, session.DID)
    if err != nil {
        return nil, fmt.Errorf("failed to get profile: %w", err)
    }

    return output, nil
}
```

## API Endpoints

- `GET /` - Home page with login form
- `GET /login?handle=<handle>` - Start OAuth flow
- `GET /callback` - OAuth callback handler
- `GET /profile` - Fetch and display user profile via XRPC
- `GET /logout` - Logout and clear session
- `GET /client-metadata.json` - OAuth client metadata

## Differences from Standard Demo

This demo differs from the standard web-demo in several ways:

1. **Additional Scope**: Includes `transition:chat.bsky` scope for chat-related APIs
2. **XRPC Usage**: Demonstrates direct XRPC client usage instead of using the high-level API
3. **Profile Display**: Shows how to fetch and render user profile data
4. **Different Port**: Runs on port 8182 by default to avoid conflicts with the standard demo

## Security Notes

- The demo runs on HTTP by default for local development
- In production, use HTTPS (set `BASE_URL` to an `https://` URL)
- Sessions are stored in memory and will be lost on restart
- For production, implement a persistent session store (Redis, database, etc.)

## Extending This Demo

You can extend this demo to:

- Fetch chat messages using the chat scope
- Display user posts and timelines
- Implement chat functionality
- Add more XRPC endpoints (search, notifications, etc.)
