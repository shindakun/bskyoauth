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

### Changed
- **SECURITY**: OAuth state entries now automatically expire after 10 minutes to prevent memory leaks
- Internal `oauthStateStore` structure enhanced with TTL tracking and expiration timestamps
- State store `get()` method now validates expiration before returning entries
- **DOCUMENTATION**: Expanded Security section in README with prominent HTTPS warnings
- **DOCUMENTATION**: Added detailed production deployment guidelines
- Example application now validates BASE_URL and warns when HTTPS is not used

### Fixed
- **SECURITY**: Fixed memory leak where abandoned OAuth authorization flows would persist indefinitely
- **SECURITY**: Fixed potential DoS vector from accumulating expired state entries
- Fixed DPoP private keys remaining in memory after failed/abandoned auth flows
- **SECURITY**: Fixed missing issuer validation allowing potential authorization code injection

### Technical Details
- OAuth state entries are now wrapped in `stateEntry` struct with `expiresAt` timestamp
- Cleanup goroutine runs every minute to purge expired entries
- State validation checks expiration on retrieval, providing defense-in-depth
- Thread-safe operations maintained with proper mutex usage
- Issuer validation performed in `CompleteAuthFlow` before token exchange
- Expected issuer stored during `StartAuthFlow` and validated during callback
- Security events logged to stderr for monitoring and alerting

### Migration Notes
- This is a backwards-compatible change with no API modifications
- Existing code will continue to work without changes
- OAuth flows must complete within 10 minutes (standard practice for OAuth state parameters)
