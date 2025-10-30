# Version History

This document tracks version changes for the bskyoauth module.

## Versioning Policy

- **v1.x.x**: Stable API, 100% backward compatibility maintained
- **Major version (v2.x.x)**: Only for breaking changes (requires updating imports)
- **Minor version (v1.x.0)**: New features, non-breaking enhancements
- **Patch version (v1.0.x)**: Bug fixes, documentation updates, internal improvements

## Current Version: v1.3.0

### v1.3.0 (2025-10-29)

**Minor version release** - Audit trail support for compliance and security monitoring

#### New Features

**Audit Trail Infrastructure:**
- `AuditEvent` struct with standardized fields (timestamp, event_type, actor, action, resource, result, error, metadata, request_id, session_id)
- `AuditLogger` interface for flexible backend implementations
- `NoOpAuditLogger` as safe default (opt-in design, zero overhead)
- 15+ standardized event type constants for consistent categorization
- Package-level functions: `SetAuditLogger()`, `GetAuditLogger()`, `LogAuditEvent()`
- Automatic context enrichment (timestamps, request IDs, session IDs)

**Built-in Audit Loggers:**
- `FileAuditLogger` - Simple append-only file logging with restrictive permissions (0600)
- `RotatingFileAuditLogger` - Daily log rotation at midnight UTC
- Thread-safe concurrent writes with mutex protection
- Automatic directory creation with proper permissions

**Comprehensive Integration:**
- **OAuth flow** (`oauth.go`):
  - `auth.start` - Flow initiation (success/failure)
  - `auth.callback` - Callback received
  - `auth.success` / `auth.failure` - Flow completion
  - `security.issuer_mismatch` - Code injection attempt detection (critical security event)
  - `security.invalid_state` - CSRF attack attempt detection
- **Token refresh** (`oauth.go`):
  - `session.refresh` - Token refresh operations (success/failure)
- **API operations** (`client.go`):
  - `api.post.create` - Post creation
  - `api.record.create` - Custom record creation (includes AT URI)
  - `api.record.read` - Record retrieval
  - `api.record.delete` - Record deletion

#### Files Added
- `audit.go` - Core audit infrastructure (159 lines)
- `audit_file.go` - File-based audit loggers (177 lines)
- `audit_test.go` - Comprehensive test suite (532 lines, 10 test functions)

#### Files Modified
- `oauth.go` - Integrated audit logging into auth flow and token refresh
- `client.go` - Integrated audit logging into API operations (CreatePost, CreateRecord, GetRecord, DeleteRecord)
- `README.md` - Added 380+ lines of audit trail documentation

#### Documentation
- New "Audit Trail" section in README with:
  - Quick start guide
  - Complete event type reference
  - JSON log format specification with field descriptions
  - Built-in logger documentation (FileAuditLogger, RotatingFileAuditLogger)
  - Custom logger examples (PostgreSQL, Splunk/SIEM integration)
  - Manual audit logging for custom events
  - Context enrichment guide
  - Compliance best practices (retention, integrity, access control, monitoring)
  - Performance considerations (buffering, rotation, sampling, compression)
  - Security event examples with JSON output

#### Testing
- 10 comprehensive audit tests covering:
  - NoOp logger behavior
  - Global logger configuration
  - Event enrichment (request ID, session ID, timestamp)
  - File logger functionality
  - Rotating logger functionality
  - Thread-safety under concurrent load (10 goroutines × 10 events)
  - Directory creation
  - Event structure validation
  - Mock logger for testing custom implementations
- All tests pass with `-race` detection
- All 22 existing tests continue to pass (no regressions)

#### Use Cases
- **Compliance**: Meets audit trail requirements for SOX, PCI-DSS, HIPAA, GDPR
- **Security Monitoring**: Real-time detection of attacks (CSRF, code injection, invalid states)
- **Forensic Analysis**: Tamper-evident trail of all sensitive operations
- **Incident Response**: Complete reconstruction of security events
- **Operational Insights**: Track authentication patterns, API usage, errors

#### Impact
- **No Breaking Changes**: 100% backward compatible
- **Opt-In Design**: Audit logging disabled by default (no performance impact)
- **Flexible**: Interface-based design supports any backend (file, database, SIEM)
- **Thread-Safe**: All loggers safe for concurrent use
- **Production-Ready**: Restrictive permissions, append-only mode, daily rotation
- **Compliance-Ready**: Structured JSON logs with complete event context

#### Issue Resolution
- Resolves Issue #17: Missing Audit Trail
- Moved to COMPLETED_ISSUES.md with comprehensive implementation notes

---

### v1.2.1 (2025-10-29)

**Patch release** - DPoP key persistence documentation and security guidance

#### Documentation Enhancements
- Added comprehensive "DPoP Key Persistence and Security Considerations" section to README
- Security trade-offs comparison table (Ephemeral vs Persisted vs Hybrid approaches)
- Three implementation options with complete code examples
- Added security warning to simple Redis example about plaintext key storage

#### New Documentation Content
1. **Option 1: Ephemeral Keys (Default)**
   - Recommended for most applications
   - Maximum security - keys never persisted
   - Automatic key rotation

2. **Option 2: Hybrid Approach (Recommended for Production)**
   - Best of both worlds
   - Ephemeral keys + token refresh for extended sessions
   - No encryption key management needed

3. **Option 3: Encrypted Persistence (Advanced)**
   - Complete SecureRedisSessionStore implementation
   - AES-256-GCM encryption example (~140 lines)
   - Security requirements checklist
   - Key management best practices

#### Additional Guidance
- Key rotation policy recommendations
- Summary recommendations by scenario (web/API/mobile/desktop)
- Security requirements for persisted keys
- Monitoring and alerting guidance

#### Issue Resolution
- Resolves Issue #16: DPoP Key Storage Considerations
- Moved to COMPLETED_ISSUES.md with comprehensive resolution notes

#### Impact
- **No Code Changes**: Documentation only
- **No Breaking Changes**: 100% backward compatible
- **Security by Default**: Ephemeral keys remain the default (secure)
- **User Choice**: Clear guidance for teams needing persistence

---

### v1.2.0 (2025-10-29)

**Minor version release** - Comprehensive security testing suite

#### New Security Tests (22 tests total)
- **CSRF Protection Tests** (8 tests): State validation, issuer validation, replay prevention, concurrent access
- **Session Security Tests** (6 tests): Hijacking/fixation prevention, expiration, cookie security flags
- **Rate Limiting Tests** (3 tests): Evasion attempts, IPv6 support, distributed attacks
- **Input Validation Fuzzing** (5 fuzz tests): Handle, post text, text fields, NSIDs, record structures

#### Files Added
- `security_csrf_test.go` - CSRF attack simulation tests
- `security_session_test.go` - Session security tests
- `security_ratelimit_test.go` - Rate limit evasion tests
- `validation_fuzz_test.go` - Fuzzing tests for validation

#### Impact
- **No Breaking Changes**: 100% backward compatible
- **Attack Simulation**: Tests simulate real-world attack scenarios
- **Fuzzing**: Continuous fuzzing to find edge cases
- **Thread Safety**: Verified under concurrent access

---

### v1.1.4 (2025-10-29)

**Documentation maintenance release** - Archived completed TODO issues

#### Changes
- Archived all completed security issues from TODO.md to new COMPLETED_ISSUES.md
- Reduced TODO.md from 757 lines to 220 lines (71% reduction)
- Improved TODO.md focus by keeping only active work items
- Added cross-reference links between TODO.md and COMPLETED_ISSUES.md
- Preserved historical documentation of all completed security improvements

#### Impact
- **Documentation**: Cleaner, more actionable TODO list
- **Maintainability**: Easier to identify pending work vs completed issues
- **Historical Record**: All completed work preserved in COMPLETED_ISSUES.md
- **Zero functional changes**: Documentation-only release

---

### v1.1.3 (2025-10-29)

**Maintenance release** - Removed empty jwt.go file

#### Changes
- Removed empty jwt.go file (only contained package declaration)
- Updated CHANGELOG.md references to clarify JWT code is in internal/jwt
- Updated TODO.md to note JWT functionality is internal-only per AT Protocol spec
- Clarified that access tokens are treated as opaque per specification

#### Impact
- **Code Cleanup**: Removed unnecessary empty file
- **Documentation**: Clearer guidance on JWT handling
- **No Breaking Changes**: JWT verification remains available in internal/jwt package

---

### v1.1.2 (2025-10-29)

**Minor feature release** - Display record ID in web demo

#### Features
- Added record ID display in web-demo after creating custom records
- New success page shows AT URI and rkey immediately after creation
- Added quick action buttons: View Record (JSON), Delete Record, Create Another
- New utility function `extractRkeyFromURI()` for parsing record keys
- Improved user experience by eliminating need to check server logs

#### Web Demo Enhancements
- Eliminated redirect after record creation
- Display full AT URI: `at://did:plc:abc.../com.demo.bskyoauth/rkey`
- Copyable record key (rkey) with user-select CSS
- One-click access to view and delete newly created records
- Styled success page matching existing web-demo design

#### Impact
- **User Experience**: Immediate feedback on record creation
- **Usability**: Easy access to record operations
- **No Breaking Changes**: Only affects web-demo example, library unchanged

---

### v1.1.1 (2025-10-29)

**Minor feature release** - Lexicon support for custom records

#### Features
- Added proper AT Protocol lexicon support for custom record types
- Created `lexicon` package with `DemoRecord` type
- Implemented CBOR marshaling/unmarshaling for custom records
- Added lexicon JSON schema at `lexicons/com/demo/bskyoauth.json`
- Automatic type registration with indigo library via `init()`
- Field validation for lexicon records (text length, timestamps)

#### New Files
- `lexicon/demo.go` - DemoRecord type with CBOR methods
- `lexicon/validation.go` - Field validation for DemoRecord
- `lexicon/demo_test.go` - Comprehensive test coverage (15+ tests)
- `lexicons/com/demo/bskyoauth.json` - AT Protocol lexicon schema

#### Changes
- Updated `client.go` with blank import to trigger lexicon registration
- Updated `internal/api/client.go` with lexicon registration
- Updated `examples/web-demo/main.go` to use typed `DemoRecord`
- GetRecord now works with custom lexicon types

#### Impact
- **Correctness**: Proper AT Protocol lexicon implementation
- **Type Safety**: Typed records instead of generic maps
- **Validation**: Built-in field validation for custom records
- **No Breaking Changes**: Existing code continues to work

---

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

### v1.1.3 (2025-10-29)

**Cleanup**
- Removed empty jwt.go file from root directory
- JWT functionality remains available in internal/jwt package (unchanged)
- Pure housekeeping cleanup from Phase 1 refactoring

**Documentation Updates**
- CHANGELOG.md: Updated JWT reference to point to internal/jwt
- TODO.md: Clarified that JWT code is internal-only per AT Protocol spec
- Removed outdated references to jwt.go and jwt_test.go

**Technical Details**
- jwt.go contained only `package bskyoauth` declaration (1 line, no content)
- File was leftover from Phase 1 refactoring when JWT moved to internal/
- Actual JWT verification code remains in internal/jwt/verify.go (unchanged)
- internal/jwt package is used internally by the library

**No Functional Changes**
- ✅ No API changes
- ✅ No behavior changes
- ✅ No new features
- ✅ No bug fixes
- ✅ Pure cleanup of empty file

**Backward Compatibility**
- ✅ 100% compatible with v1.1.2
- ✅ No breaking changes
- ✅ jwt.go was empty, removal has zero impact
- ✅ All existing code continues to work

**Why This Matters**
- Cleaner codebase without confusing empty files
- Accurate documentation reflecting current structure
- Clear indication that JWT is internal-only (per AT Protocol OAuth spec)

### v1.1.2 (2025-10-29)

**Enhancements**
- Display record ID (rkey) after creating custom records in web-demo
- Added success page showing full AT URI and extracted rkey
- Quick action buttons for viewing or deleting newly created records
- Improved user experience with immediate feedback

**Changes**
- `examples/web-demo/main.go`: Added `extractRkeyFromURI()` utility function
- `examples/web-demo/main.go`: Added `renderRecordCreatedPage()` for success display
- `examples/web-demo/main.go`: Updated `createRecordHandler` to show success page instead of redirect

**User Experience Improvements**
- Users can now immediately see and copy the rkey of created records
- Direct "View Record (JSON)" button to see record data immediately
- Direct "Delete Record" button with confirmation for newly created records
- "Create Another Record" link to easily create more records
- No need to check server logs or manually type rkeys

**UI Features**
- Styled success page with clear visual hierarchy
- Copyable rkey text with user-select styling
- Color-coded success message
- Monospace display for AT URI and rkey
- Responsive button layout

**Backward Compatibility**
- ✅ 100% compatible with v1.1.1
- ✅ No API changes to core library
- ✅ Only affects web-demo example UI
- ✅ No breaking changes

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
