# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- OAuth state store now includes automatic expiration and cleanup mechanism
- Added `DefaultStateStoreTTL` constant (10 minutes) for OAuth state entry lifetime
- Added `DefaultCleanupInterval` constant (1 minute) for cleanup goroutine interval
- Added automatic background cleanup goroutine to remove expired OAuth state entries
- Added graceful shutdown support for cleanup goroutine via `stop()` method
- **SECURITY**: Added comprehensive HTTPS enforcement documentation in README
- **SECURITY**: Added production deployment security checklist
- **SECURITY**: Added reverse proxy configuration examples (nginx, Caddy)
- Added HTTPS validation warnings in web-demo example application
- Added security best practices section covering cookies, session storage, rate limiting
- **SECURITY**: Added issuer validation to prevent authorization code injection attacks
- **SECURITY**: Added `ErrIssuerMismatch` error for detecting attack attempts
- **SECURITY**: Added security event logging for issuer mismatch detection
- Added `ExpectedIssuer` field to OAuth state for validation during callback
- **SECURITY**: Added IP-based rate limiting using golang.org/x/time/rate
- Added `RateLimiter` type with configurable rate and burst limits
- Added rate limiting middleware for HTTP endpoints
- Web-demo example now includes rate limiting on auth and API endpoints
- Added comprehensive test suite for rate limiter (ratelimit_test.go)
- Added 10 test cases covering rate limiting behavior, IP extraction, cleanup, and concurrency
- Added comprehensive test suite for session management (session_test.go)
- Added 15 test cases covering session store operations, ID generation, concurrency, and stress testing
- Added comprehensive test suite for Client functionality (client_test.go)
- Added 16 test cases covering client initialization, metadata, session management, and edge cases

### Changed
- **SECURITY**: OAuth state entries now automatically expire after 10 minutes to prevent memory leaks
- Internal `oauthStateStore` structure enhanced with TTL tracking and expiration timestamps
- State store `get()` method now validates expiration before returning entries
- **DOCUMENTATION**: Expanded Security section in README with prominent HTTPS warnings
- **DOCUMENTATION**: Added detailed production deployment guidelines
- Example application now validates BASE_URL and warns when HTTPS is not used
- **SECURITY**: Session cookies now include Secure flag when using HTTPS
- **SECURITY**: Session cookies now have 30-day MaxAge expiration
- Logout handler now properly clears cookies with matching security attributes

### Fixed
- **SECURITY**: Fixed memory leak where abandoned OAuth authorization flows would persist indefinitely
- **SECURITY**: Fixed potential DoS vector from accumulating expired state entries
- Fixed DPoP private keys remaining in memory after failed/abandoned auth flows
- **SECURITY**: Fixed missing issuer validation allowing potential authorization code injection
- **CRITICAL**: Fixed DPoP proof replay detection by improving JTI uniqueness
- **SECURITY**: Fixed error information disclosure - sanitized error messages to prevent leaking internal details
- **CRITICAL**: Fixed DPoP nonce not persisting across requests causing replay errors

### Technical Details
- OAuth state entries are now wrapped in `stateEntry` struct with `expiresAt` timestamp
- Cleanup goroutine runs every minute to purge expired entries
- State validation checks expiration on retrieval, providing defense-in-depth
- Thread-safe operations maintained with proper mutex usage
- Issuer validation performed in `CompleteAuthFlow` before token exchange
- Expected issuer stored during `StartAuthFlow` and validated during callback
- Security events logged to stderr for monitoring and alerting
- DPoP JTI now generated with `generateUniqueJTI()` using 24 bytes of cryptographic random data
- Each DPoP proof guaranteed unique with 192 bits of entropy
- DPoP nonce now persisted in Session struct and reused across requests
- `NewDPoPTransport()` accepts nonce parameter to initialize with existing nonce
- All client methods (CreatePost, CreateRecord, DeleteRecord) update session nonce after requests
- Prevents "DPoP proof replayed" errors on subsequent API calls
- Error messages sanitized: detailed errors logged to stderr, generic messages returned to users
- Two error locations sanitized: auth metadata requests and token exchange failures
- Rate limiting implemented using token bucket algorithm from golang.org/x/time/rate
- Separate rate limiters for auth endpoints (5 req/s) and API endpoints (10 req/s)
- IP-based rate limiting with X-Forwarded-For support for proxied requests
- Automatic cleanup of idle rate limiters to prevent memory leaks
- Cookie security: Secure flag automatically enabled for HTTPS deployments
- Cookie expiration: 30-day MaxAge prevents indefinite session lifetime
- Cookie attributes preserved during logout for proper cookie deletion

### Migration Notes
- This is a backwards-compatible change with no API modifications
- Existing code will continue to work without changes
- OAuth flows must complete within 10 minutes (standard practice for OAuth state parameters)
