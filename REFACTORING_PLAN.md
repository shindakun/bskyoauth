# Library Refactoring Plan for bskyoauth

## Current Structure Analysis

### Current State
- Single package `bskyoauth` with 25 Go files (8,331 total lines)
- Largest files: `oauth.go` (748 lines), `client.go` (539 lines)
- ~300 total functions across all files
- Mix of concerns: OAuth flow, DPoP, JWT, sessions, rate limiting, security headers, validation, logging

### Pain Points Identified

1. **Large Monolithic Package**
   - All functionality in one package makes it hard to understand boundaries
   - No clear separation between public API and internal implementation
   - Difficult to navigate and find specific functionality

2. **Mixed Responsibilities in `client.go`**
   - Client struct has HTTP handlers (`LoginHandler`, `CallbackHandler`)
   - Client struct has session management methods
   - Client struct has API methods (`CreatePost`, `CreateRecord`)
   - Client struct has metadata methods
   - Violates Single Responsibility Principle

3. **`oauth.go` is Too Large** (748 lines)
   - OAuth state management
   - Token exchange
   - Token refresh
   - HTTP client management
   - PAR (Pushed Authorization Request)
   - Multiple internal types mixed with public API

4. **No Clear Internal vs External API**
   - Everything is potentially importable
   - Hard to refactor without breaking changes
   - No protection for implementation details

5. **Tight Coupling**
   - `Client` struct knows about HTTP handlers
   - Session management embedded in Client
   - DPoP transport tightly coupled to oauth flow

6. **Testing Complexity**
   - Large test files mirror large source files
   - Difficult to test components in isolation
   - Mock setup is repetitive across test files

---

## Proposed Package Structure

```
bskyoauth/
├── client.go              # Main Client type and constructor (SIMPLIFIED)
├── types.go               # Public types and interfaces
├── errors.go              # Public error types
├── constants.go           # Public constants (ApplicationType, etc.)
│
├── internal/              # Internal implementation packages
│   ├── oauth/
│   │   ├── flow.go        # OAuth flow orchestration
│   │   ├── state.go       # State management
│   │   ├── token.go       # Token exchange and refresh
│   │   └── metadata.go    # Server metadata discovery
│   │
│   ├── dpop/
│   │   ├── transport.go   # DPoP HTTP transport
│   │   ├── proof.go       # DPoP proof creation
│   │   └── keys.go        # DPoP key generation
│   │
│   ├── jwt/
│   │   ├── verify.go      # JWT verification
│   │   ├── jwks.go        # JWKS cache and fetching
│   │   └── parse.go       # JWT parsing utilities
│   │
│   ├── session/
│   │   ├── store.go       # Session store interface and implementation
│   │   ├── memory.go      # Memory-based session store
│   │   └── session.go     # Session type and methods
│   │
│   ├── api/
│   │   ├── posts.go       # Post creation methods
│   │   ├── records.go     # Generic record operations
│   │   └── client.go      # XRPC client wrapper
│   │
│   ├── http/
│   │   ├── handlers.go    # HTTP handler implementations
│   │   ├── middleware.go  # Rate limiting, security headers
│   │   └── timeout.go     # Timeout configuration
│   │
│   └── validation/
│       ├── handle.go      # Handle validation
│       ├── post.go        # Post text validation
│       └── record.go      # Record validation
│
├── logger/                # Public logging package (stays as-is or slight refactor)
│   ├── logger.go
│   └── context.go
│
└── examples/              # Examples stay at top level
    └── web-demo/
```

---

## Detailed Refactoring Plan

### Phase 1: Create Internal Package Structure (Non-Breaking)

**Goal:** Introduce `internal/` packages without changing public API

**Timeline:** 2-3 weeks

#### Step 1.1: Create `internal/oauth/` (Week 1, Days 1-2)
- Move OAuth flow logic from `oauth.go`
- Extract state store to `internal/oauth/state.go`
- Extract token operations to `internal/oauth/token.go`
- Extract metadata discovery to `internal/oauth/metadata.go`
- Keep public methods like `StartAuthFlow`, `CompleteAuthFlow`, `RefreshToken` in root as thin wrappers

**Files affected:**
- Create: `internal/oauth/flow.go`, `state.go`, `token.go`, `metadata.go`
- Modify: `oauth.go` (becomes thin wrapper)
- Tests: Move/refactor `oauth_test.go` → `internal/oauth/*_test.go`

#### Step 1.2: Create `internal/dpop/` (Week 1, Days 3-4)
- Move `dpop.go` → `internal/dpop/transport.go`
- Extract proof creation to `internal/dpop/proof.go`
- Extract key generation to `internal/dpop/keys.go`
- Keep public `GenerateDPoPKey()` in root package or re-export

**Files affected:**
- Create: `internal/dpop/transport.go`, `proof.go`, `keys.go`
- Modify: `dpop.go` (becomes thin wrapper or deleted)
- Tests: Move/refactor `dpop_test.go` → `internal/dpop/*_test.go`

#### Step 1.3: Create `internal/jwt/` (Week 1, Day 5)
- Move `jwt.go` → `internal/jwt/verify.go`
- Extract JWKS cache to `internal/jwt/jwks.go`
- Keep any public JWT utilities in root if needed

**Files affected:**
- Create: `internal/jwt/verify.go`, `jwks.go`
- Modify: `jwt.go` (becomes thin wrapper or deleted)
- Tests: Move/refactor `jwt_test.go` → `internal/jwt/*_test.go`

#### Step 1.4: Create `internal/session/` (Week 2, Days 1-2)
- Move `session.go` → `internal/session/session.go`
- Move memory store to `internal/session/memory.go`
- Keep `Session` type and `SessionStore` interface in root `types.go`

**Files affected:**
- Create: `internal/session/session.go`, `memory.go`, `store.go`
- Modify: `session.go` (keep types, move implementation)
- Create: `types.go` (consolidate public types)
- Tests: Move/refactor `session_test.go` → `internal/session/*_test.go`

#### Step 1.5: Create `internal/api/` (Week 2, Days 3-4)
- Extract `CreatePost`, `CreateRecord`, `DeleteRecord` from `client.go`
- Create dedicated API client wrapper
- Keep methods on `Client` as thin wrappers

**Files affected:**
- Create: `internal/api/posts.go`, `records.go`, `client.go`
- Modify: `client.go` (delegate to internal/api)
- Tests: Extract from `client_test.go` → `internal/api/*_test.go`

#### Step 1.6: Create `internal/http/` (Week 2, Day 5)
- Extract HTTP handlers from `client.go`
- Move rate limiting to `internal/http/middleware.go`
- Move security headers to `internal/http/middleware.go`
- Keep handler methods on `Client` returning the handlers

**Files affected:**
- Create: `internal/http/handlers.go`, `middleware.go`
- Modify: `client.go` (delegate to internal/http)
- Move: `ratelimit.go` → `internal/http/ratelimit.go`
- Move: `securityheaders.go` → `internal/http/security.go`
- Tests: Move `ratelimit_test.go`, `securityheaders_test.go` to internal/http

#### Step 1.7: Create `internal/validation/` (Week 3, Day 1)
- Move `validation.go` → `internal/validation/`
- Split by concern (handle, post, record)
- Re-export public validation functions from root

**Files affected:**
- Create: `internal/validation/handle.go`, `post.go`, `record.go`
- Modify: `validation.go` (becomes thin wrapper)
- Tests: Move `validation_test.go` → `internal/validation/*_test.go`

#### Step 1.8: Testing and Documentation (Week 3, Days 2-5)
- Run full test suite with race detection
- Update documentation if needed
- Verify backward compatibility
- Performance testing
- Update examples if needed

---

### Phase 2: Refactor Client Struct (Potentially Breaking)

**Goal:** Simplify `Client` struct and separate concerns

**Timeline:** 1-2 weeks

**Current Client responsibilities:**
- Configuration holder
- OAuth orchestrator
- Session manager
- API client
- HTTP handler provider

**Proposed Structure:**

```go
// Root package - client.go
type Client struct {
    config  *Config
    oauth   *oauth.Manager
    session session.Store
    api     *api.Client
}

type Config struct {
    BaseURL         string
    ClientID        string
    RedirectURI     string
    ClientName      string
    ApplicationType string
    Scopes          []string
}

// Simplified constructors
func NewClient(baseURL string) *Client
func NewClientWithOptions(opts ClientOptions) *Client

// OAuth methods (delegate to internal/oauth)
func (c *Client) StartAuthFlow(ctx context.Context, handle string) (*AuthFlowState, error)
func (c *Client) CompleteAuthFlow(ctx context.Context, code, state, issuer string) (*Session, error)
func (c *Client) RefreshToken(ctx context.Context, session *Session) (*Session, error)

// API methods (delegate to internal/api)
func (c *Client) CreatePost(ctx context.Context, session *Session, text string) error
func (c *Client) CreateRecord(ctx context.Context, session *Session, collection string, record map[string]interface{}) (*atproto.RepoCreateRecord_Output, error)
func (c *Client) DeleteRecord(ctx context.Context, session *Session, collection, rkey string) error

// Session methods (delegate to session store)
func (c *Client) GetSession(sessionID string) (*Session, error)
func (c *Client) UpdateSession(sessionID string, newSession *Session) error
func (c *Client) DeleteSession(sessionID string) error

// HTTP handlers (delegate to internal/http)
func (c *Client) ClientMetadataHandler() http.HandlerFunc
func (c *Client) LoginHandler() http.HandlerFunc
func (c *Client) CallbackHandler(onSuccess func(...)) http.HandlerFunc
```

**Benefits:**
- `Client` becomes a facade/coordinator
- Each internal package has clear responsibility
- Easier to test individual components
- Internal implementations can be refactored freely

---

### Phase 3: Improve Type Organization

**Goal:** Better organize public types and interfaces

**Timeline:** Part of Phase 2

**Create `types.go` in root:**
```go
// Public types that users interact with
type Session struct { ... }
type AuthFlowState struct { ... }
type ClientOptions struct { ... }

// Public interfaces
type SessionStore interface { ... }
```

**Create `constants.go` in root:**
```go
const (
    ApplicationTypeWeb = "web"
    ApplicationTypeNative = "native"
)
```

---

### Phase 4: Extract Middleware/Utilities

**Goal:** Make middleware reusable and testable

**Timeline:** 1 week

**internal/http/middleware.go:**
```go
package http

// Rate limiting middleware
func RateLimitMiddleware(limiter *rate.Limiter) func(http.Handler) http.Handler

// Security headers middleware
func SecurityHeadersMiddleware(opts SecurityHeadersOptions) func(http.Handler) http.Handler

// Logging middleware
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler
```

**Benefits:**
- Middleware can be tested independently
- Can be composed easily
- Can be used outside of Client struct
- Standard Go middleware pattern

---

### Phase 5: Improve Testing Structure

**Goal:** Make tests more focused and maintainable

**Timeline:** Ongoing

**Current:** Large test files mirror large source files

**Proposed:** Test files mirror new package structure

```
internal/
├── oauth/
│   ├── flow.go
│   ├── flow_test.go      # Tests only flow logic
│   ├── token.go
│   └── token_test.go     # Tests only token operations
├── dpop/
│   ├── transport.go
│   ├── transport_test.go
│   ├── proof.go
│   └── proof_test.go
└── ...
```

**Create test helpers package:**
```
internal/testutil/
├── mock_server.go        # Mock OAuth/AT Proto server
├── fixtures.go           # Test fixtures (sessions, tokens, etc.)
└── helpers.go            # Common test utilities
```

---

## Migration Strategy

### Option A: Big Bang (Not Recommended)
- Refactor everything at once
- High risk of breaking changes
- Long development time
- Difficult to review

### Option B: Incremental Migration (Recommended) ✅

**Step 1:** Create internal packages, keep public API unchanged (Phase 1)
- ✅ Non-breaking
- ✅ Can be done incrementally
- ✅ Tests continue to pass
- ✅ Users see no changes

**Step 2:** Improve internal implementations (Phase 2-4)
- ✅ Still non-breaking (internal changes only)
- ✅ Better structure emerges
- ✅ Easier to test

**Step 3:** Optionally introduce v2 API (Phase 2 breaking changes)
- Only if significant API improvements are desired
- Can use Go modules major version (`/v2`)
- Maintain v1 for backward compatibility

---

## Benefits of Refactoring

### For Users
1. **Clearer API** - Easier to understand what's public vs internal
2. **Better Documentation** - Focused packages with clear purposes
3. **Stability** - Internal refactors won't break their code
4. **Gradual Migration** - Can adopt new patterns incrementally

### For Maintainers
1. **Easier to Navigate** - Logical package structure
2. **Easier to Test** - Isolated components
3. **Easier to Refactor** - Internal packages can change freely
4. **Easier to Review** - Smaller, focused files
5. **Better Separation of Concerns** - Each package has single responsibility

### For Contributors
1. **Clear Boundaries** - Know where to add new features
2. **Smaller PRs** - Changes are more focused
3. **Less Risk** - Internal changes don't affect API
4. **Better Examples** - Clearer patterns to follow

---

## Example: Before vs After

### Before (current)
```go
// client.go - 539 lines mixing concerns
type Client struct {
    BaseURL         string
    ClientID        string
    RedirectURI     string
    ClientName      string
    ApplicationType string
    Scopes          []string
    SessionStore    SessionStore
}

// All these in one file:
func (c *Client) CreatePost(...)         // API
func (c *Client) LoginHandler(...)       // HTTP
func (c *Client) StartAuthFlow(...)      // OAuth
func (c *Client) GetSession(...)         // Session
func (c *Client) GetClientMetadata(...)  // Metadata
```

### After (proposed)
```go
// client.go - ~150 lines, clear facade
type Client struct {
    config  *Config
    oauth   *oauth.Manager      // internal/oauth
    api     *api.Client          // internal/api
    session session.Store        // internal/session
}

// Delegates to specialized internal packages
func (c *Client) CreatePost(...)      { return c.api.CreatePost(...) }
func (c *Client) StartAuthFlow(...)   { return c.oauth.StartFlow(...) }
func (c *Client) GetSession(...)      { return c.session.Get(...) }

// internal/api/posts.go - focused on API operations
// internal/oauth/flow.go - focused on OAuth flow
// internal/http/handlers.go - focused on HTTP handlers
```

---

## Risks and Mitigations

### Risk 1: Breaking Changes
- **Mitigation:** Phase 1 is completely non-breaking
- **Mitigation:** Use internal packages to protect implementation
- **Mitigation:** Only break API in v2 if necessary

### Risk 2: Increased Complexity
- **Mitigation:** More packages, but each is simpler
- **Mitigation:** Clear naming and documentation
- **Mitigation:** Examples showing new structure

### Risk 3: Import Cycles
- **Mitigation:** Clear dependency hierarchy (internal packages don't import from root)
- **Mitigation:** Use interfaces to break cycles if needed

### Risk 4: Test Refactoring
- **Mitigation:** Refactor tests incrementally alongside code
- **Mitigation:** Keep existing tests passing during migration
- **Mitigation:** Add new focused tests for internal packages

---

## Timeline Estimate

### Phase 1: Internal Packages (2-3 weeks)
- Week 1: Create structure, move dpop/jwt/validation
- Week 2: Move oauth logic, session management
- Week 3: Move API methods, HTTP handlers, testing

### Phase 2: Client Simplification (1-2 weeks)
- Week 1: Refactor Client struct, update tests
- Week 2: Documentation, examples

### Phase 3-4: Polish (1 week)
- Improve middleware, extract utilities
- Update README, add migration guide

### Phase 5: Testing Improvements (Ongoing)
- Can be done incrementally
- Improve as you touch each package

**Total: 4-6 weeks** for complete refactoring

---

## Current Status

### Completed
- ✅ Analysis of current structure
- ✅ Research of Go best practices
- ✅ Designed proposed package structure
- ✅ Created detailed refactoring plan
- ✅ **Phase 1: Internal Package Extraction - COMPLETE**
  - ✅ Step 1.1: Created internal/oauth/ (state, token, metadata)
  - ✅ Step 1.2: Created internal/dpop/ (transport, proof, keys)
  - ✅ Step 1.3: Created internal/jwt/ (verify, jwks)
  - ✅ Step 1.4: Created internal/session/ (session, memory store)
  - ✅ Step 1.5: Created internal/api/ (posts, records, client wrapper)
  - ✅ Step 1.6: Created internal/http/ (handlers, middleware)
  - ✅ Step 1.7: Created internal/validation/ (handle, post, record)
  - ✅ Step 1.8: Testing and documentation verification

### Results
- **100% backward compatibility maintained** - All public APIs unchanged
- **All tests pass** with race detection enabled
- **Significant code reduction** in root package files (50-78% per file)
- **Clear separation of concerns** - Internal implementation hidden
- **Better code organization** - Functionality split into focused packages
- **Foundation established** for Phase 2 improvements

### Next Steps
- Phase 2: Refactor Client Struct (potentially breaking, requires major version bump)
- Phase 3: Documentation and Examples Enhancement
- Phase 4: Performance Optimizations

---

## Recommendation

**Start with Phase 1** as it provides immediate benefits with zero breaking changes:
1. Better code organization
2. Clear separation of concerns
3. Easier to navigate and understand
4. Foundation for future improvements
5. **Zero impact on existing users**

The refactoring can be done incrementally, one internal package at a time, with tests passing at each step. This minimizes risk and allows for course corrections along the way.
