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

### Planned for v1.1.0 (Future)
- (Add new features here as they are planned)

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
