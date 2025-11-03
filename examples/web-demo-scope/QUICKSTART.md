# Quick Start Guide - Chat OAuth Demo

## What This Demo Does

This example demonstrates:

1. **Custom OAuth Scopes** - Requests the `transition:chat.bsky` scope in addition to standard scopes
2. **XRPC Direct Usage** - Shows how to make direct XRPC calls to Bluesky APIs
3. **Profile Fetching** - Uses `app.bsky.actor.getProfile` to fetch and display user profile information

## Quick Start

### 1. Start the Server

From this directory:

```bash
go run main.go
```

The server will start on port **8182** (different from the main demo's 8181).

### 2. Access the Demo

Open your browser to:
```
http://localhost:8182
```

### 3. Login

Enter your Bluesky handle (e.g., `yourname.bsky.social`) and click "Login with Bluesky".

You'll be redirected to Bluesky's authorization page where you'll see the requested scopes:
- `atproto` - Basic AT Protocol access
- `transition:generic` - Generic transition scope
- `transition:chat.bsky` - Chat-specific scope

### 4. View Your Profile

After successful authentication, click the "View My Profile (XRPC)" button.

The demo will:
1. Resolve your PDS endpoint from your DID
2. Create a DPoP-authenticated XRPC client
3. Call `app.bsky.actor.getProfile` to fetch your profile
4. Display:
   - Your avatar
   - Display name and handle
   - Bio/description
   - Follower count
   - Following count
   - Post count
   - Raw JSON response from the API

## Understanding the Code

### Custom Scopes Configuration

Located in [main.go:97-101](main.go#L97-L101):

```go
client := bskyoauth.NewClientWithOptions(bskyoauth.ClientOptions{
    BaseURL:    baseURL,
    HTTPClient: httpClient,
    Scopes:     []string{"atproto", "transition:generic", "transition:chat.bsky"},
})
```

### XRPC Profile Fetch

Located in [main.go:297-346](main.go#L297-L346):

The `getProfile` function shows how to:
1. Resolve a user's PDS endpoint from their DID
2. Create an XRPC client with DPoP authentication
3. Make authenticated API calls
4. Handle DPoP nonce updates

### Key Components

- **DPoP Transport**: Handles proof-of-possession token authentication
- **Identity Resolution**: Converts DIDs to PDS endpoints
- **XRPC Client**: Direct access to AT Protocol APIs
- **Token Refresh**: Automatic refresh of expired access tokens

## Environment Variables

Customize the demo with these environment variables:

```bash
# Server configuration
export BASE_URL="http://localhost:8182"
export SERVER_PORT="8182"

# Session timeout
export SESSION_TIMEOUT_DAYS="30"

# Rate limiting (format: "requests/sec,burst")
export RATE_LIMIT_AUTH="5,10"
export RATE_LIMIT_API="10,20"
```

## Running Both Demos Simultaneously

You can run both the standard demo and this chat demo at the same time:

**Terminal 1** (Standard Demo):
```bash
cd examples/web-demo
go run main.go
# Runs on http://localhost:8181
```

**Terminal 2** (Chat Demo):
```bash
cd examples/web-demo-chat
go run main.go
# Runs on http://localhost:8182
```

## Troubleshooting

### Port Already in Use

If port 8182 is in use, change it:

```bash
export SERVER_PORT="8183"
export BASE_URL="http://localhost:8183"
go run main.go
```

### Token Refresh Issues

If you see token refresh errors:
1. The demo automatically refreshes tokens when they expire
2. Check the console logs for detailed error messages
3. Try logging out and logging in again

### Profile Fetch Fails

If profile fetching fails:
1. Ensure you have a valid Bluesky account
2. Check that your handle/DID resolves correctly
3. Look for error messages in the console logs

## Next Steps

Extend this demo to:
- Fetch and display user posts
- Implement chat message retrieval using the chat scope
- Add timeline/feed functionality
- Implement search features
- Add notification handling

## Security Notes

- **Development Only**: This demo uses HTTP for local development
- **Production**: Use HTTPS by setting `BASE_URL` to an `https://` URL
- **Session Storage**: Uses in-memory storage (cleared on restart)
- **For Production**: Implement persistent session storage (Redis, database, etc.)
