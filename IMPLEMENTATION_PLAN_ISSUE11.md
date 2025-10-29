# Implementation Plan: Issue #11 - Structured Logging and Monitoring

## Summary

This implementation adds comprehensive structured logging to the bskyoauth library using Go's standard `log/slog` package. The logging system is:

- **Environment-Aware**: Automatically configures based on BASE_URL
  - **Localhost**: Text format, Info level (development-friendly)
  - **Production**: JSON format, Error level (production-ready, minimal noise)
- **Optional**: Default logger is silent unless explicitly enabled
- **Zero Dependencies**: Uses only Go standard library (1.21+)
- **Context-Aware**: Request IDs and session IDs for correlation
- **Security-Focused**: Logs authentication, session lifecycle, errors, and security events

**Key Functions:**
- `NewLoggerFromEnv(baseURL)` - One-line setup with automatic environment detection
- `LogLevelFromEnv(baseURL)` - Get appropriate log level for environment
- `SetLogger(logger)` - Configure custom logger
- `WithRequestID(ctx, id)` / `WithSessionID(ctx, id)` - Add correlation IDs

## Problem Statement

The library currently has limited security event logging:
- No failed login attempt logging
- No session lifecycle events
- No suspicious activity monitoring
- Errors logged to stderr inconsistently
- No structured logging for easy parsing and monitoring
- No correlation IDs for request tracking

## Solution: Use Go's Standard Library `log/slog`

**Why slog?**
- Built into Go standard library (Go 1.21+) - no external dependencies
- Structured logging with key-value pairs
- Multiple output formats (JSON, text)
- Log levels (Debug, Info, Warn, Error)
- Context-aware logging
- Production-ready and well-tested

**Why NOT logrus or zap?**
- Adds external dependencies to the library
- slog is now the standard Go logging approach
- slog performance is comparable to zap
- Library users may have their own logging preferences

## Design Principles

1. **Optional and Configurable**: Users can provide their own `*slog.Logger` or use default
2. **Zero Dependencies**: Use only Go standard library
3. **Non-Breaking**: Default logger writes to `io.Discard` (silent) unless user configures
4. **Contextual**: Include request IDs, session IDs, DIDs for correlation
5. **Security-Focused**: Log authentication events, session lifecycle, errors
6. **Production-Ready**: JSON format for log aggregation systems

## Implementation Details

### File: logger.go (NEW)

```go
package bskyoauth

import (
	"context"
	"io"
	"log/slog"
	"os"
)

// Logger is the package-level logger instance.
// By default, logs are discarded. Call SetLogger() to enable logging.
var Logger *slog.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))

// SetLogger sets the package-level logger.
// This should be called during application initialization to enable logging.
//
// Example:
//
//	// Text logging to stdout (development)
//	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
//	    Level: slog.LevelInfo,
//	})
//	bskyoauth.SetLogger(slog.New(handler))
//
//	// JSON logging to stdout (production)
//	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
//	    Level: slog.LevelError,
//	})
//	bskyoauth.SetLogger(slog.New(handler))
func SetLogger(logger *slog.Logger) {
	if logger != nil {
		Logger = logger
	}
}

// NewDefaultLogger creates a default logger with JSON output to stdout.
// Useful for quick setup without manual configuration.
func NewDefaultLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
}

// NewTextLogger creates a text logger for development/debugging.
func NewTextLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	}))
}

// LogLevelFromEnv determines the appropriate log level based on environment.
// Checks BASE_URL to determine if running locally or in production.
// Returns Info level for localhost, Error level for production.
func LogLevelFromEnv(baseURL string) slog.Level {
	// Parse the base URL
	if baseURL == "" {
		return slog.LevelError // Default to production (Error level)
	}

	// Check if localhost
	if strings.Contains(baseURL, "localhost") ||
		strings.Contains(baseURL, "127.0.0.1") ||
		strings.Contains(baseURL, "[::1]") {
		return slog.LevelInfo // Development: Info level
	}

	return slog.LevelError // Production: Error level
}

// NewLoggerFromEnv creates a logger with appropriate settings based on environment.
// Uses BASE_URL to determine if running locally (text, Info) or production (JSON, Error).
//
// Example:
//
//	logger := bskyoauth.NewLoggerFromEnv(os.Getenv("BASE_URL"))
//	bskyoauth.SetLogger(logger)
func NewLoggerFromEnv(baseURL string) *slog.Logger {
	level := LogLevelFromEnv(baseURL)

	// Localhost: use text format for readability
	if strings.Contains(baseURL, "localhost") ||
		strings.Contains(baseURL, "127.0.0.1") ||
		strings.Contains(baseURL, "[::1]") {
		return NewTextLogger(level)
	}

	// Production: use JSON format for log aggregation
	return NewDefaultLogger(level)
}

// contextKey type for context values
type contextKey string

const (
	// ContextKeyRequestID is the context key for request IDs
	ContextKeyRequestID contextKey = "request_id"
	// ContextKeySessionID is the context key for session IDs
	ContextKeySessionID contextKey = "session_id"
)

// WithRequestID adds a request ID to the context for correlation.
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, ContextKeyRequestID, requestID)
}

// WithSessionID adds a session ID to the context for correlation.
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, ContextKeySessionID, sessionID)
}

// LoggerFromContext returns a logger with context values attached.
// Extracts request_id and session_id from context if present.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	logger := Logger

	if requestID, ok := ctx.Value(ContextKeyRequestID).(string); ok && requestID != "" {
		logger = logger.With("request_id", requestID)
	}

	if sessionID, ok := ctx.Value(ContextKeySessionID).(string); ok && sessionID != "" {
		logger = logger.With("session_id", sessionID)
	}

	return logger
}

// GenerateRequestID generates a unique request ID for correlation.
// Uses cryptographic randomness for uniqueness.
func GenerateRequestID() string {
	return GenerateSessionID() // Reuse session ID generation (already crypto-random)
}
```

### File: oauth.go (MODIFICATIONS)

Add logging to authentication flow:

```go
// In StartAuthFlow()
func (c *Client) StartAuthFlow(ctx context.Context, handle string) (*AuthFlowState, error) {
	logger := LoggerFromContext(ctx)
	logger.Info("starting OAuth flow",
		"handle", handle,
		"client_id", c.baseURL+"/client-metadata.json")

	// ... existing code ...

	if err != nil {
		logger.Error("OAuth flow failed",
			"handle", handle,
			"error", err,
			"stage", "metadata_fetch")
		return nil, fmt.Errorf("failed to resolve handle: %w", err)
	}

	// ... after successful state creation ...
	logger.Info("OAuth flow started successfully",
		"handle", handle,
		"state", state,
		"issuer", metadata.Issuer)

	return &AuthFlowState{...}, nil
}

// In CompleteAuthFlow()
func (c *Client) CompleteAuthFlow(ctx context.Context, code, state, iss string) (*Session, error) {
	logger := LoggerFromContext(ctx)
	logger.Info("completing OAuth flow",
		"state", state,
		"issuer", iss)

	// ... existing code ...

	if err == ErrInvalidState {
		logger.Warn("invalid or expired OAuth state",
			"state", state,
			"error", err)
		return nil, err
	}

	if err == ErrIssuerMismatch {
		logger.Error("issuer mismatch detected - possible attack",
			"state", state,
			"expected_issuer", flowState.ExpectedIssuer,
			"actual_issuer", iss,
			"security_event", "issuer_mismatch")
		return nil, err
	}

	// ... after successful token exchange ...
	logger.Info("OAuth flow completed successfully",
		"state", state,
		"did", session.DID,
		"issuer", iss)

	return session, nil
}
```

### File: session.go (MODIFICATIONS)

Add logging to session lifecycle:

```go
// In MemorySessionStore.Set()
func (m *MemorySessionStore) Set(sessionID string, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[sessionID] = sessionEntry{
		session:   session,
		expiresAt: time.Now().Add(m.ttl),
	}

	Logger.Info("session created",
		"session_id", sessionID,
		"did", session.DID,
		"expires_at", time.Now().Add(m.ttl))

	return nil
}

// In MemorySessionStore.Get()
func (m *MemorySessionStore) Get(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	entry, exists := m.sessions[sessionID]
	if !exists {
		Logger.Debug("session not found",
			"session_id", sessionID)
		return nil, ErrSessionNotFound
	}

	if time.Now().After(entry.expiresAt) {
		Logger.Info("session expired",
			"session_id", sessionID,
			"expired_at", entry.expiresAt)
		return nil, ErrSessionNotFound
	}

	Logger.Debug("session retrieved",
		"session_id", sessionID,
		"did", entry.session.DID)

	return entry.session, nil
}

// In MemorySessionStore.Delete()
func (m *MemorySessionStore) Delete(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, exists := m.sessions[sessionID]; exists {
		Logger.Info("session deleted",
			"session_id", sessionID,
			"did", entry.session.DID)
	}

	delete(m.sessions, sessionID)
	return nil
}

// In cleanup goroutine
func (m *MemorySessionStore) cleanup() {
	// ... existing code ...
	if len(expired) > 0 {
		Logger.Info("cleaned up expired sessions",
			"count", len(expired))
	}
}
```

### File: client.go (MODIFICATIONS)

Add logging to API operations:

```go
// In LoginHandler()
func (c *Client) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := WithRequestID(r.Context(), GenerateRequestID())
		logger := LoggerFromContext(ctx)

		handle := r.URL.Query().Get("handle")
		if handle == "" {
			logger.Warn("login attempt with missing handle",
				"remote_addr", r.RemoteAddr)
			http.Error(w, "handle parameter required", http.StatusBadRequest)
			return
		}

		// Validate handle
		if err := ValidateHandle(handle); err != nil {
			logger.Warn("login attempt with invalid handle",
				"handle", handle,
				"remote_addr", r.RemoteAddr,
				"error", err)
			http.Error(w, fmt.Sprintf("invalid handle: %v", err), http.StatusBadRequest)
			return
		}

		// ... rest of handler ...
	}
}

// In CreatePost()
func (c *Client) CreatePost(ctx context.Context, session *Session, text string) error {
	logger := LoggerFromContext(ctx).With(
		"did", session.DID,
		"operation", "create_post")

	// Validate post text
	if err := ValidatePostText(text); err != nil {
		logger.Warn("post creation failed - invalid text",
			"error", err,
			"text_length", len(text))
		return fmt.Errorf("invalid post text: %w", err)
	}

	// ... create post ...

	if err != nil {
		logger.Error("post creation failed",
			"error", err,
			"pds", session.PDS)
		return err
	}

	logger.Info("post created successfully",
		"uri", resp.URI,
		"cid", resp.CID)

	return nil
}
```

### File: ratelimit.go (MODIFICATIONS)

Add logging to rate limiting:

```go
// In Allow()
func (rl *RateLimiter) Allow(ip string) bool {
	// ... existing code ...

	allowed := limiter.Allow()
	if !allowed {
		Logger.Warn("rate limit exceeded",
			"ip", ip,
			"endpoint", "unknown") // Add endpoint tracking if needed
	}

	return allowed
}
```

### File: logger_test.go (NEW)

```go
package bskyoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestSetLogger(t *testing.T) {
	// Save original logger
	originalLogger := Logger
	defer func() { Logger = originalLogger }()

	// Create test logger
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, nil))

	SetLogger(testLogger)

	if Logger != testLogger {
		t.Error("SetLogger did not update global logger")
	}

	// Test logging works
	Logger.Info("test message", "key", "value")

	if !strings.Contains(buf.String(), "test message") {
		t.Error("Logger did not write to buffer")
	}
}

func TestSetLoggerNil(t *testing.T) {
	originalLogger := Logger
	defer func() { Logger = originalLogger }()

	SetLogger(nil)

	// Logger should remain unchanged
	if Logger != originalLogger {
		t.Error("SetLogger(nil) should not change logger")
	}
}

func TestNewDefaultLogger(t *testing.T) {
	logger := NewDefaultLogger(slog.LevelInfo)
	if logger == nil {
		t.Fatal("NewDefaultLogger returned nil")
	}

	// Logger should be functional (won't test output to stdout)
}

func TestNewTextLogger(t *testing.T) {
	logger := NewTextLogger(slog.LevelDebug)
	if logger == nil {
		t.Fatal("NewTextLogger returned nil")
	}
}

func TestWithRequestID(t *testing.T) {
	ctx := context.Background()
	requestID := "test-request-123"

	ctx = WithRequestID(ctx, requestID)

	if got := ctx.Value(ContextKeyRequestID); got != requestID {
		t.Errorf("Expected request ID %q, got %v", requestID, got)
	}
}

func TestWithSessionID(t *testing.T) {
	ctx := context.Background()
	sessionID := "test-session-456"

	ctx = WithSessionID(ctx, sessionID)

	if got := ctx.Value(ContextKeySessionID); got != sessionID {
		t.Errorf("Expected session ID %q, got %v", sessionID, got)
	}
}

func TestLoggerFromContext(t *testing.T) {
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, nil))
	SetLogger(testLogger)
	defer func() { Logger = slog.New(slog.NewJSONHandler(bytes.NewBuffer(nil), nil)) }()

	ctx := context.Background()
	ctx = WithRequestID(ctx, "req-123")
	ctx = WithSessionID(ctx, "sess-456")

	logger := LoggerFromContext(ctx)
	logger.Info("test message")

	output := buf.String()
	if !strings.Contains(output, "req-123") {
		t.Error("Logger did not include request_id")
	}
	if !strings.Contains(output, "sess-456") {
		t.Error("Logger did not include session_id")
	}
}

func TestLoggerFromContextEmpty(t *testing.T) {
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, nil))
	SetLogger(testLogger)
	defer func() { Logger = slog.New(slog.NewJSONHandler(bytes.NewBuffer(nil), nil)) }()

	ctx := context.Background()

	logger := LoggerFromContext(ctx)
	logger.Info("test message")

	// Should not contain request_id or session_id keys
	output := buf.String()
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse log output: %v", err)
	}

	if _, ok := logEntry["request_id"]; ok {
		t.Error("Log entry should not contain request_id when not in context")
	}
	if _, ok := logEntry["session_id"]; ok {
		t.Error("Log entry should not contain session_id when not in context")
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := GenerateRequestID()
	id2 := GenerateRequestID()

	if id1 == "" {
		t.Error("GenerateRequestID returned empty string")
	}
	if id1 == id2 {
		t.Error("GenerateRequestID returned duplicate IDs")
	}
	if len(id1) < 16 {
		t.Error("GenerateRequestID returned ID that seems too short")
	}
}

func TestLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		name     string
		baseURL  string
		expected slog.Level
	}{
		{"localhost", "http://localhost:8181", slog.LevelInfo},
		{"localhost with https", "https://localhost:8181", slog.LevelInfo},
		{"127.0.0.1", "http://127.0.0.1:8181", slog.LevelInfo},
		{"IPv6 localhost", "http://[::1]:8181", slog.LevelInfo},
		{"production domain", "https://example.com", slog.LevelError},
		{"production subdomain", "https://app.example.com", slog.LevelError},
		{"empty string", "", slog.LevelError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := LogLevelFromEnv(tt.baseURL)
			if level != tt.expected {
				t.Errorf("LogLevelFromEnv(%q) = %v, want %v", tt.baseURL, level, tt.expected)
			}
		})
	}
}

func TestNewLoggerFromEnv(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
	}{
		{"localhost", "http://localhost:8181"},
		{"production", "https://example.com"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewLoggerFromEnv(tt.baseURL)
			if logger == nil {
				t.Errorf("NewLoggerFromEnv(%q) returned nil", tt.baseURL)
			}

			// Verify logger works (won't test output format)
			logger.Info("test message")
		})
	}
}
```

### File: README.md (ADDITIONS)

Add new section after Security Headers:

```markdown
### Structured Logging

The library uses Go's standard `log/slog` for structured logging. By default, logging is disabled (logs go to `io.Discard`). Enable logging during application initialization.

**Easy Setup (Automatic Environment Detection):**

```go
import (
    "os"
    "github.com/shindakun/bskyoauth"
)

func main() {
    // Automatically configures logging based on BASE_URL:
    // - Localhost: Text format, Info level
    // - Production: JSON format, Error level
    logger := bskyoauth.NewLoggerFromEnv(os.Getenv("BASE_URL"))
    bskyoauth.SetLogger(logger)

    // ... rest of application ...
}
```

**Manual Configuration:**

```go
import (
    "log/slog"
    "os"
    "github.com/shindakun/bskyoauth"
)

func main() {
    // JSON logging for production (log aggregation systems)
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelError, // Only errors in production
    }))
    bskyoauth.SetLogger(logger)

    // OR: Text logging for development
    logger := bskyoauth.NewTextLogger(slog.LevelInfo) // Info and above
    bskyoauth.SetLogger(logger)
}
```

**Request Correlation:**

Use context to track requests with correlation IDs:

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    // Add request ID to context
    ctx := bskyoauth.WithRequestID(r.Context(), bskyoauth.GenerateRequestID())

    // All logging in this request will include request_id
    flowState, err := client.StartAuthFlow(ctx, handle)
    // ...
}
```

**What Gets Logged:**

- **Authentication Events**: Login attempts, OAuth flow start/complete, failures
- **Session Lifecycle**: Session creation, retrieval, expiration, deletion
- **API Operations**: Post creation, record operations, errors
- **Security Events**: Rate limiting, issuer mismatches, invalid inputs
- **System Events**: Session cleanup, expired state cleanup

**Log Levels:**
- **Debug**: Session retrievals, detailed flow information
- **Info**: Successful operations, session lifecycle, OAuth completion
- **Warn**: Rate limiting, invalid inputs, expired sessions
- **Error**: Failed authentications, API errors, security events

**Example Log Output (JSON):**

```json
{"time":"2025-10-28T20:00:00Z","level":"INFO","msg":"OAuth flow started successfully","handle":"alice.bsky.social","state":"abc123","issuer":"https://bsky.social"}
{"time":"2025-10-28T20:00:05Z","level":"INFO","msg":"session created","session_id":"xyz789","did":"did:plc:abc123","expires_at":"2025-11-27T20:00:05Z"}
{"time":"2025-10-28T20:00:10Z","level":"ERROR","msg":"issuer mismatch detected - possible attack","state":"abc123","expected_issuer":"https://bsky.social","actual_issuer":"https://evil.com","security_event":"issuer_mismatch"}
```

**Custom Logger:**

You can provide your own `*slog.Logger` configured however you prefer:

```go
// Send logs to a file
file, _ := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
logger := slog.New(slog.NewJSONHandler(file, &slog.HandlerOptions{
    Level: slog.LevelInfo,
}))
bskyoauth.SetLogger(logger)

// Send logs to a remote service (example with custom handler)
// ... implement custom slog.Handler ...
```
```

### File: CHANGELOG.md (ADDITIONS)

```markdown
### Added
- **LOGGING**: Added comprehensive structured logging with Go's `log/slog`
  - Package-level logger with `SetLogger()` for configuration
  - Default logger writes to `io.Discard` (silent unless configured)
  - Context-aware logging with request ID and session ID correlation
  - `WithRequestID()` and `WithSessionID()` for adding correlation to context
  - `LoggerFromContext()` extracts context values for automatic correlation
  - `GenerateRequestID()` for unique request tracking
  - `NewDefaultLogger()` and `NewTextLogger()` for quick setup
  - **Environment-based configuration:**
    - `NewLoggerFromEnv()` automatically configures logging based on BASE_URL
    - `LogLevelFromEnv()` determines appropriate log level
    - Localhost: Text format, Info level (development-friendly)
    - Production: JSON format, Error level (production-ready)
  - JSON and text output formats
  - Configurable log levels (Debug, Info, Warn, Error)
  - Zero external dependencies (uses Go standard library)

- **LOGGING EVENTS**: Comprehensive event logging across the library
  - OAuth flow: start, completion, failures with handles and issuers
  - Session lifecycle: creation, retrieval, expiration, deletion with DIDs
  - API operations: post creation, record operations with results
  - Security events: rate limiting, issuer mismatches, invalid inputs
  - System events: cleanup operations, session counts

- **TESTS**: Added comprehensive logging tests (logger_test.go)
  - Test logger configuration and setup
  - Test context correlation (request ID, session ID)
  - Test logger extraction from context
  - Test request ID generation
  - Test environment-based log level detection
  - Test NewLoggerFromEnv with localhost and production URLs
  - 11 new test cases for logging functionality

### Changed
- OAuth flow now logs authentication attempts and results
- Session store logs all session lifecycle events
- Client methods log API operations and errors
- Rate limiter logs when limits are exceeded
- Error logging includes structured context (no more stderr only)
```

## Implementation Checklist

- [ ] Create logger.go with slog setup and context helpers
- [ ] Create logger_test.go with comprehensive tests
- [ ] Modify oauth.go to add logging to StartAuthFlow and CompleteAuthFlow
- [ ] Modify session.go to add logging to session lifecycle
- [ ] Modify client.go to add logging to API operations
- [ ] Modify ratelimit.go to add logging to rate limiting
- [ ] Update README.md with logging documentation
- [ ] Update CHANGELOG.md with logging additions
- [ ] Run all tests and verify they pass
- [ ] Test logging output with example application
- [ ] Update TODO.md moving #11 to completed section
- [ ] Commit all changes

## Testing Plan

1. **Unit Tests**: All logger functions and context helpers
2. **Integration Tests**: Verify logging in OAuth flow
3. **Manual Tests**:
   - Run web-demo with logging enabled (text output)
   - Run web-demo with logging enabled (JSON output)
   - Verify log correlation with request IDs
   - Trigger various log events (success, errors, rate limiting)

## Design Decisions

**Q: Why not log by default?**
A: Libraries should not be opinionated about logging. Let users configure it. Default to silent (io.Discard).

**Q: Why slog and not logrus or zap?**
A: slog is Go standard library (Go 1.21+), zero dependencies, production-ready, and the Go team's recommended approach.

**Q: How to handle sensitive data?**
A: Never log passwords, tokens, or full request bodies. Only log handles, DIDs, session IDs (which are opaque identifiers).

**Q: Should we log to stderr like before?**
A: No - centralize all logging through slog. Users can configure output destination (stdout, file, remote service).

**Estimated Effort:** 4-6 hours

**NOTE:** Delete this file (IMPLEMENTATION_PLAN_ISSUE11.md) when implementation is completed and committed.
