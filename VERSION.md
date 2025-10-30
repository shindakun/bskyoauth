# Version History

This document tracks version changes for the bskyoauth module.

## Versioning Policy

- **v1.x.x**: Stable API, 100% backward compatibility maintained
- **Major version (v2.x.x)**: Only for breaking changes (requires updating imports)
- **Minor version (v1.x.0)**: New features, non-breaking enhancements
- **Patch version (v1.0.x)**: Bug fixes, documentation updates, internal improvements

## Current Version: v1.0.0

### v1.0.0 (2025-10-29)

**Initial stable release** - Production-ready Bluesky OAuth library

#### Features
- Complete OAuth 2.0 authorization code flow with PKCE
- DPoP (RFC 9449) for token binding with ECDSA P-256
- Automatic token refresh with expiration tracking
- PAR (Pushed Authorization Request) support
- JWKS caching and JWT verification
- Handle resolution and PDS discovery

#### Session Management
- Built-in memory session store
- Custom session store interface for Redis, database, etc.
- Automatic session cleanup and expiration
- Thread-safe concurrent access

#### API Operations
- Create posts (app.bsky.feed.post)
- Create custom records with any collection NSID
- Delete records from repository
- Automatic DPoP nonce management
- Replay protection and retry logic

#### Middleware & Security
- IP-based rate limiting with configurable limits
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- Environment-aware CSP policies (localhost vs production)
- HTTP request/response logging middleware
- Composable middleware pattern

#### Validation
- Handle validation (length, format, syntax)
- Post text validation (length, UTF-8, null bytes)
- Record validation (createdAt format, depth limits)
- NSID (collection) validation

#### Developer Experience
- Structured logging with slog
- Environment-based log configuration
- Context-based request/correlation IDs
- Comprehensive error types
- 100+ tests with race detection
- Full example application included

#### Architecture
- Clean separation between public API and internal implementation
- `internal/` packages protect implementation details
- Thin wrapper pattern for public exports
- Well-organized by concern (oauth, dpop, jwt, session, api, validation)
- Testing utilities (internal/testutil) with fixtures and mock servers

#### Testing
- All tests pass with -race detection
- No known vulnerabilities (govulncheck clean)
- Passes golangci-lint with all checks enabled
- Automated pre-commit hooks included

---

## Upcoming Changes

Track minor version changes here for future releases.

### v1.1.1 (2025-10-29)

**Bug Fixes**
- Fixed GetRecord to work with custom lexicon types (com.demo.bskyoauth)
- Resolved "unrecognized lexicon type" error by implementing proper type registration

**New Package: lexicon**
- `lexicon.DemoRecord` - Typed struct for com.demo.bskyoauth records
- Full CBOR marshaling/unmarshaling support
- Automatic type registration with indigo library
- Validation methods for required fields

**New Files**
- `lexicon/demo.go` - DemoRecord type definition with CBOR methods (~200 lines)
- `lexicon/validation.go` - Field validation (text length, RFC3339 timestamps)
- `lexicon/demo_test.go` - Comprehensive unit tests for marshaling and validation
- `lexicons/com/demo/bskyoauth.json` - AT Protocol lexicon JSON schema

**Implementation Details**
- Defined DemoRecord struct with JSON and CBOR tags following AT Protocol standards
- Implemented MarshalCBOR() and UnmarshalCBOR() methods manually
- Registered type in init() function for automatic discovery
- GetRecord now properly decodes custom lexicon types
- Added validation for text length (max 10000 bytes / 3000 graphemes)
- Added validation for RFC3339 timestamp format

**API Enhancements**
- `DemoRecord.Validate()` - Validates all required fields
- CreateRecord accepts both `map[string]interface{}` and typed `*lexicon.DemoRecord`
- GetRecord returns `map[string]interface{}` compatible with lexicon types
- Example updated to use typed DemoRecord for better type safety

**Testing**
- 15+ unit tests for CBOR marshaling/unmarshaling
- Round-trip testing for data integrity
- Validation tests for all edge cases
- Unicode and long text handling verified

**Backward Compatibility**
- ✅ 100% backward compatible with v1.1.0
- ✅ CreateRecord still accepts `map[string]interface{}`
- ✅ GetRecord API unchanged
- ✅ Existing code continues to work without modifications
- ✅ Optional: Import `lexicon` package for typed access

**Developer Experience**
- Type-safe record creation with lexicon.DemoRecord
- Clear error messages for validation failures
- Follows AT Protocol lexicon best practices
- Foundation for adding more custom record types

### v1.1.0 (2025-10-29)

**New Features**
- Added `GetRecord()` method to retrieve records from any collection
- Complements existing `CreateRecord()` and `DeleteRecord()` operations
- Supports custom collections including `com.demo.bskyoauth`
- Full DPoP authentication and nonce management
- Automatic token refresh on expiration

**API Changes**
- `Client.GetRecord(ctx, session, collection, rkey)` - Public API
- `internal/api.Client.GetRecord(ctx, req)` - Internal implementation
- Returns `map[string]interface{}` for maximum flexibility

**Example Usage**
```go
// Get a record by collection and rkey
record, err := client.GetRecord(ctx, session, "com.demo.bskyoauth", "3k7qxyz...")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Record text: %s\n", record["text"])
```

**Changes**
- `internal/api/client.go`: Added `GetRecordRequest` type and `GetRecord()` method (~90 lines)
- `client.go`: Added public `GetRecord()` wrapper method (~40 lines)
- `examples/web-demo/main.go`: Added `/get-record` endpoint for demonstration (~85 lines)

**Backward Compatibility**
- ✅ 100% backward compatible with v1.0.0
- ✅ All existing APIs unchanged
- ✅ No breaking changes

### Planned for v1.0.1 (Future)
- (Add bug fixes here as they are identified)

---

## Release Process

1. Update this VERSION.md file with changes
2. Update CHANGELOG.md if present
3. Run full test suite: `go test -race ./...`
4. Run linting: `golangci-lint run`
5. Run security scan: `govulncheck ./...`
6. Commit changes
7. Create git tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z"`
8. Push commits: `git push origin main`
9. Push tag: `git push origin vX.Y.Z`

## Version Numbering

Following semantic versioning (https://semver.org/):

- **MAJOR** version (v2.0.0): Breaking API changes
  - Changing function signatures
  - Removing public APIs
  - Changing behavior in incompatible ways

- **MINOR** version (v1.1.0): New features, backward compatible
  - Adding new public functions/methods
  - Adding new optional parameters
  - Adding new middleware
  - Performance improvements

- **PATCH** version (v1.0.1): Bug fixes, backward compatible
  - Fixing bugs
  - Documentation improvements
  - Internal refactoring
  - Security fixes (non-breaking)

## Stability Guarantee

For all v1.x.x releases:
- ✅ All public APIs will remain stable
- ✅ Function signatures will not change
- ✅ Behavior will remain consistent
- ✅ Internal packages can evolve freely
- ✅ Existing code will continue to work
