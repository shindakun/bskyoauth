# Implementation Plan: Context Timeout Handling (Issue #13)

## Overview

Add explicit timeout configurations to all HTTP operations to prevent requests from hanging indefinitely. This improves reliability and prevents resource exhaustion from stuck connections.

## Current State

**Problem Areas:**
- ❌ `http.Get()` calls without context (3 occurrences in oauth.go)
- ❌ `http.NewRequest()` without context (2 occurrences in oauth.go)
- ❌ No default timeout on HTTP clients
- ❌ No timeout documentation for users

**What Works:**
- ✅ Some requests already use `http.NewRequestWithContext()` (4 occurrences)
- ✅ Context is passed to public methods

## Implementation Plan

### Phase 1: Update HTTP Client Creation

#### 1.1 Create HTTP Client with Timeout

**File:** `oauth.go`, `client.go`

Add a package-level HTTP client with sensible defaults:

```go
var (
    // defaultHTTPClient is the HTTP client used for OAuth and API requests.
    // Configurable via SetHTTPClient() for testing or custom configurations.
    defaultHTTPClient = &http.Client{
        Timeout: 30 * time.Second,
        Transport: &http.Transport{
            DialContext: (&net.Dialer{
                Timeout:   10 * time.Second,  // Connection timeout
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
```

**Timeout Strategy:**
- **Total Request Timeout**: 30 seconds (covers entire request lifecycle)
- **Connection Timeout**: 10 seconds (TCP handshake)
- **TLS Handshake**: 10 seconds
- **Response Headers**: 10 seconds (time to receive headers)
- **Idle Connections**: Reuse connections for 90 seconds

### Phase 2: Update oauth.go HTTP Calls

#### 2.1 Replace http.Get() with Context-Aware Requests

**Location:** oauth.go - 3 occurrences

**Current:**
```go
resp, err := http.Get(metadataURL)
```

**Updated:**
```go
req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
if err != nil {
    return nil, fmt.Errorf("failed to create metadata request: %w", err)
}
resp, err := defaultHTTPClient.Do(req)
```

**Locations to update:**
1. Line ~208: `StartAuthFlow()` - auth server metadata
2. Line ~292: `CompleteAuthFlow()` - token endpoint metadata
3. Line ~420: `RefreshToken()` - token endpoint metadata

#### 2.2 Update Existing http.NewRequest() Calls

**Location:** oauth.go - `exchangeCodeForTokens()` at line ~593

**Current:**
```go
req, _ := http.NewRequest("POST", tokenEndpoint, strings.NewReader(data.Encode()))
```

**Updated:**
```go
req, err := http.NewRequestWithContext(ctx, "POST", tokenEndpoint, strings.NewReader(data.Encode()))
if err != nil {
    return nil, fmt.Errorf("failed to create token request: %w", err)
}
```

#### 2.3 Update HTTP Client Usage

**Location:** All `client.Do(req)` calls

**Current:**
```go
client := &http.Client{}
resp, err := client.Do(req)
```

**Updated:**
```go
resp, err := defaultHTTPClient.Do(req)
```

### Phase 3: Add Timeout Configuration Options

#### 3.1 Add Client-Level Timeout Configuration

**File:** `types.go`, `client.go`

Add optional timeout configuration to ClientOptions:

```go
// ClientOptions contains optional configuration for the OAuth client.
type ClientOptions struct {
    BaseURL      string
    ClientName   string
    Scopes       []string
    SessionStore SessionStore
    HTTPClient   *http.Client  // NEW: Optional custom HTTP client
}
```

Update `NewClientWithOptions()`:

```go
func NewClientWithOptions(opts ClientOptions) *Client {
    // ... existing code ...

    // Use custom HTTP client if provided
    if opts.HTTPClient != nil {
        SetHTTPClient(opts.HTTPClient)
    }

    return &Client{
        ClientID:     clientID,
        ClientName:   clientName,
        RedirectURI:  redirectURI,
        Scopes:       scopes,
        SessionStore: opts.SessionStore,
    }
}
```

### Phase 4: Context Propagation

#### 4.1 Ensure Context Propagation Throughout

**Check all public methods receive context:**

Currently context-aware:
- ✅ `StartAuthFlow(ctx, handle)`
- ✅ `CompleteAuthFlow(ctx, code, state, issuer)`
- ✅ `RefreshToken(ctx, session)`
- ✅ `CreatePost(ctx, session, text)`
- ✅ `CreateRecord(ctx, session, collection, record)`
- ✅ `DeleteRecord(ctx, session, collection, rkey)`

All public API methods already accept context - no changes needed.

### Phase 5: Error Handling

#### 5.1 Add Timeout Error Detection

**File:** `errors.go` (create if doesn't exist)

```go
import (
    "errors"
    "net"
    "os"
)

// IsTimeoutError checks if an error is a timeout error.
func IsTimeoutError(err error) bool {
    if err == nil {
        return false
    }

    // Check for context deadline exceeded
    if errors.Is(err, context.DeadlineExceeded) {
        return true
    }

    // Check for net.Error timeout
    var netErr net.Error
    if errors.As(err, &netErr) && netErr.Timeout() {
        return true
    }

    // Check for os.ErrDeadlineExceeded
    if errors.Is(err, os.ErrDeadlineExceeded) {
        return true
    }

    return false
}
```

#### 5.2 Add Timeout Error Logging

Update error logging to identify timeouts:

```go
if err != nil {
    if IsTimeoutError(err) {
        logger.Error("request timeout",
            "url", metadataURL,
            "error", err)
    } else {
        logger.Error("request failed",
            "url", metadataURL,
            "error", err)
    }
    return nil, fmt.Errorf("failed to retrieve metadata: %w", err)
}
```

### Phase 6: Testing

#### 6.1 Add Timeout Tests

**File:** `timeout_test.go` (new)

```go
package bskyoauth

import (
    "context"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
)

func TestHTTPTimeout(t *testing.T) {
    // Create server that never responds
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(60 * time.Second) // Sleep longer than timeout
    }))
    defer server.Close()

    // Set custom client with 1 second timeout for testing
    oldClient := GetHTTPClient()
    defer SetHTTPClient(oldClient)

    testClient := &http.Client{Timeout: 1 * time.Second}
    SetHTTPClient(testClient)

    // Test that request times out
    client := NewClient(server.URL)
    _, err := client.StartAuthFlow(context.Background(), "test.bsky.social")

    if err == nil {
        t.Error("expected timeout error, got nil")
    }

    if !IsTimeoutError(err) {
        t.Errorf("expected timeout error, got: %v", err)
    }
}

func TestContextCancellation(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(10 * time.Second)
    }))
    defer server.Close()

    // Create context with short timeout
    ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
    defer cancel()

    client := NewClient(server.URL)
    _, err := client.StartAuthFlow(ctx, "test.bsky.social")

    if err == nil {
        t.Error("expected error from cancelled context")
    }

    if !errors.Is(err, context.DeadlineExceeded) {
        t.Errorf("expected context.DeadlineExceeded, got: %v", err)
    }
}

func TestSetHTTPClient(t *testing.T) {
    customClient := &http.Client{Timeout: 5 * time.Second}
    SetHTTPClient(customClient)

    if GetHTTPClient() != customClient {
        t.Error("SetHTTPClient did not update the client")
    }

    // Restore default
    SetHTTPClient(&http.Client{Timeout: 30 * time.Second})
}
```

#### 6.2 Test Timeout in Integration

Add timeout scenarios to existing tests:
- Slow metadata endpoint
- Slow token endpoint
- Network connection timeout
- Cancelled context propagation

### Phase 7: Documentation

#### 7.1 Update README.md

Add timeout configuration section:

```markdown
## Timeout Configuration

The library uses sensible default timeouts for all HTTP operations:
- **Request Timeout**: 30 seconds (total request time)
- **Connection Timeout**: 10 seconds (TCP handshake)
- **TLS Handshake**: 10 seconds
- **Response Headers**: 10 seconds

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
```

#### 7.2 Update CHANGELOG.md

```markdown
### Added
- **Context Timeout Handling**: Added explicit timeout configurations (Issue #13)
  - Default 30 second timeout for all HTTP requests
  - Connection timeout: 10 seconds
  - TLS handshake timeout: 10 seconds
  - Response header timeout: 10 seconds
  - Configurable via `ClientOptions.HTTPClient`
  - `SetHTTPClient()` and `GetHTTPClient()` for global configuration
  - All `http.Get()` calls replaced with context-aware requests
  - `IsTimeoutError()` helper for timeout detection
  - Comprehensive timeout logging
  - Test coverage for timeout scenarios

### Changed
- HTTP requests now use `defaultHTTPClient` with timeout configuration
- All `http.Get()` replaced with `http.NewRequestWithContext()`
- Better error messages for timeout scenarios
```

## Implementation Strategy

### Recommended Approach

1. **Phase 1** - Create HTTP client with timeouts (core infrastructure)
2. **Phase 2** - Update all HTTP calls to use context and default client
3. **Phase 3** - Add configuration options
4. **Phase 4** - Verify context propagation (already done)
5. **Phase 5** - Add timeout error handling
6. **Phase 6** - Write tests
7. **Phase 7** - Update documentation

### Breaking Changes

**None** - All changes are backwards compatible:
- Default timeouts added (previously none = infinite)
- New optional configuration (HTTPClient in ClientOptions)
- New utility functions (SetHTTPClient, GetHTTPClient, IsTimeoutError)
- Existing API remains unchanged

### Key Decisions

1. **Default Timeout: 30 seconds**
   - Reasonable for OAuth flows
   - Covers slow networks
   - Prevents indefinite hangs
   - Can be customized per deployment

2. **Connection Pooling**
   - Reuse connections for performance
   - Max 10 connections per host
   - 90 second idle timeout
   - Standard Go best practices

3. **Error Handling**
   - Distinguish timeouts from other errors
   - Provide `IsTimeoutError()` helper
   - Log timeouts distinctly
   - Preserve error chains

## Timeout Values Rationale

| Timeout | Value | Reasoning |
|---------|-------|-----------|
| Total Request | 30s | OAuth metadata and token requests should complete quickly. 30s allows for slow networks while preventing indefinite hangs. |
| Connection | 10s | TCP handshake should be fast. 10s handles slow DNS and connection establishment. |
| TLS Handshake | 10s | TLS negotiation is typically <1s. 10s provides generous buffer. |
| Response Headers | 10s | Server should send headers quickly. 10s catches hung servers. |
| Idle Connection | 90s | Reuse connections for multiple requests. Standard Go practice. |

## Testing Strategy

1. **Unit Tests**
   - Test SetHTTPClient/GetHTTPClient
   - Test IsTimeoutError with various error types
   - Mock slow servers

2. **Integration Tests**
   - Test actual timeout behavior
   - Test context cancellation
   - Test timeout in all HTTP operations

3. **Manual Testing**
   - Test with slow networks
   - Test with unresponsive servers
   - Verify logging output

## Success Criteria

- ✅ All HTTP requests have explicit timeouts
- ✅ Timeouts are configurable
- ✅ Timeout errors are distinguishable
- ✅ Context cancellation works correctly
- ✅ Comprehensive test coverage
- ✅ Documentation with examples
- ✅ No breaking changes

## Timeline Estimate

- Phase 1 (HTTP Client): 30 minutes
- Phase 2 (Update Calls): 1 hour
- Phase 3 (Configuration): 30 minutes
- Phase 4 (Context Check): 15 minutes
- Phase 5 (Error Handling): 30 minutes
- Phase 6 (Testing): 1.5 hours
- Phase 7 (Documentation): 45 minutes

**Total**: ~5 hours

## References

- [Go HTTP Client Timeouts](https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/)
- [Context and Timeouts](https://go.dev/blog/context)
- [net/http Client](https://pkg.go.dev/net/http#Client)
- [Transport Timeouts](https://pkg.go.dev/net/http#Transport)
