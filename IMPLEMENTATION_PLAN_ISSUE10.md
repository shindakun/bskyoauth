# Implementation Plan for Issue #10: Security Headers Middleware

## Overview
Add security headers middleware to the **main bskyoauth library** (not just the example) that automatically relaxes headers for localhost development while maintaining strict security for production deployments.

## Key Design Principles

1. **Library-level implementation**: Security headers middleware lives in the main library so all users benefit
2. **Automatic localhost detection**: Relaxed headers for `localhost` and `127.0.0.1`, strict for everything else
3. **Zero configuration**: Works out of the box with sensible defaults
4. **User-friendly development**: No CSP violations during local development
5. **Production-ready**: Strict security headers for production deployments

## 1. Create Security Headers Middleware (`securityheaders.go` in main library)

**Location**: `/Users/steve/go/src/github.com/shindakun/bskyoauth/securityheaders.go`

### Implementation Structure:

```go
package bskyoauth

import (
    "net/http"
    "strings"
)

// SecurityHeadersMiddleware returns middleware that adds security headers to responses.
// Automatically detects localhost and relaxes CSP policy for development.
// HSTS is only enabled for HTTPS connections (not localhost).
func SecurityHeadersMiddleware() func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Detect if this is localhost
            isLocalhost := isLocalhostRequest(r)

            // Detect if this is HTTPS
            isHTTPS := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

            // Apply security headers
            applySecurityHeaders(w, isLocalhost, isHTTPS)

            next.ServeHTTP(w, r)
        })
    }
}

// isLocalhostRequest detects if the request is from localhost
func isLocalhostRequest(r *http.Request) bool {
    host := r.Host
    // Remove port if present
    if idx := strings.Index(host, ":"); idx != -1 {
        host = host[:idx]
    }

    return host == "localhost" ||
           host == "127.0.0.1" ||
           host == "[::1]" ||
           host == "0.0.0.0"
}

// applySecurityHeaders applies appropriate headers based on environment
func applySecurityHeaders(w http.ResponseWriter, isLocalhost, isHTTPS bool) {
    // Always apply these headers
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-XSS-Protection", "1; mode=block")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

    // CSP: relaxed for localhost, strict for production
    if isLocalhost {
        w.Header().Set("Content-Security-Policy", getLocalhostCSP())
    } else {
        w.Header().Set("Content-Security-Policy", getProductionCSP())
    }

    // HSTS: only for HTTPS in production (not localhost)
    if isHTTPS && !isLocalhost {
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    }
}

// getLocalhostCSP returns relaxed CSP for localhost development
func getLocalhostCSP() string {
    return "default-src 'self'; " +
           "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
           "style-src 'self' 'unsafe-inline'; " +
           "img-src 'self' data:; " +
           "connect-src 'self'; " +
           "form-action 'self'"
}

// getProductionCSP returns strict CSP for production
func getProductionCSP() string {
    return "default-src 'self'; " +
           "script-src 'self'; " +
           "style-src 'self'; " +
           "img-src 'self' data:; " +
           "connect-src 'self'; " +
           "form-action 'self'; " +
           "frame-ancestors 'none'; " +
           "base-uri 'self'"
}
```

## 2. Create Test Suite (`securityheaders_test.go`)

**Location**: `/Users/steve/go/src/github.com/shindakun/bskyoauth/securityheaders_test.go`

**Test cases** (minimum 12 tests):

### Localhost Detection Tests (4 tests)
- Test localhost is detected
- Test 127.0.0.1 is detected
- Test production domain is NOT localhost
- Test localhost with port is detected

### CSP Policy Tests (3 tests)
- Test localhost CSP includes 'unsafe-inline' and 'unsafe-eval'
- Test production CSP excludes 'unsafe-inline'
- Test production CSP includes 'frame-ancestors none'

### HSTS Tests (3 tests)
- Test HSTS set for HTTPS in production
- Test HSTS NOT set for HTTPS on localhost
- Test HSTS NOT set for HTTP

### Header Application Tests (2 tests)
- Test all required headers present
- Test middleware execution doesn't break handler

## 3. Update `examples/web-demo/main.go`

Simply wrap the mux with the security middleware:

```go
func main() {
    baseURL := os.Getenv("BASE_URL")
    if baseURL == "" {
        baseURL = "http://localhost:8181"
    }

    // ... existing setup ...

    // Set up HTTP handlers
    mux := http.NewServeMux()
    mux.HandleFunc("/", homeHandler(client))
    // ... other handlers ...

    // Apply security headers middleware
    handler := bskyoauth.SecurityHeadersMiddleware()(mux)

    log.Println("Server starting on :8181")
    log.Println("✓ Security headers enabled (auto-detects localhost)")
    log.Fatal(http.ListenAndServe(":8181", handler))
}
```

No need for environment detection in the example - the library handles it automatically!

## 4. Key Differences from Previous Implementation

### Previous Implementation (REJECTED):
- ❌ Security middleware in example code only
- ❌ Manual environment detection based on BASE_URL
- ❌ Required configuration
- ❌ Users had to copy code to their own apps

### New Implementation (CORRECT):
- ✅ Security middleware in main library
- ✅ Automatic localhost detection from HTTP request
- ✅ Zero configuration required
- ✅ All users get security headers automatically
- ✅ Works with any hosting setup (detects from request, not BASE_URL)
- ✅ Handles reverse proxies (checks X-Forwarded-Proto)

## 5. Benefits of Library-Level Implementation

1. **Reusability**: Every user of the library gets security headers
2. **Consistency**: Same security policy across all deployments
3. **Maintenance**: Security updates benefit all users
4. **Testing**: Library-level tests ensure correctness
5. **Documentation**: Single source of truth for security headers
6. **Best practices**: Encourages secure defaults

## 6. Localhost Detection Logic

The middleware detects localhost from the **HTTP request**, not configuration:

```go
// Checks r.Host header
localhost           -> localhost
127.0.0.1          -> localhost
[::1]              -> localhost
localhost:8181     -> localhost (strips port)
127.0.0.1:8181     -> localhost (strips port)
example.com        -> production
192.168.1.1        -> production
```

This works regardless of how the app is deployed (reverse proxy, Docker, etc.)

## 7. HTTPS Detection

Checks two sources:
1. `r.TLS != nil` - direct HTTPS connection
2. `r.Header.Get("X-Forwarded-Proto") == "https"` - reverse proxy

This ensures HSTS works correctly behind reverse proxies like nginx, Caddy, or cloud load balancers.

## 8. Documentation Updates

### README.md:

Add new section after "Security Features":

```markdown
### Security Headers

The library includes automatic security headers middleware:

```go
// Simply wrap your handler
handler := bskyoauth.SecurityHeadersMiddleware()(mux)
http.ListenAndServe(":8080", handler)
```

**Automatic Behavior:**
- **Localhost**: Relaxed CSP with 'unsafe-inline' for easy development
- **Production**: Strict CSP, no 'unsafe-inline', includes frame-ancestors
- **HSTS**: Automatically enabled for HTTPS (not localhost)

**Headers Applied:**
- Content-Security-Policy (environment-aware)
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Strict-Transport-Security (HTTPS production only)
- X-XSS-Protection: 1; mode=block
- Referrer-Policy: strict-origin-when-cross-origin

No configuration needed - the middleware automatically detects localhost vs production from the HTTP request.
```

### CHANGELOG.md:

```markdown
### Added
- **SECURITY**: Added `SecurityHeadersMiddleware()` to main library
  - Automatic localhost detection for relaxed CSP in development
  - Strict CSP for production (no unsafe-inline)
  - HSTS automatically enabled for HTTPS (not localhost)
  - Works with reverse proxies (checks X-Forwarded-Proto)
  - Zero configuration required
  - 12+ comprehensive test cases
```

## 9. Implementation Order

1. **Step 1**: Create `securityheaders.go` in main library
2. **Step 2**: Create `securityheaders_test.go` with comprehensive tests
3. **Step 3**: Run tests and verify all pass
4. **Step 4**: Update `examples/web-demo/main.go` to use middleware
5. **Step 5**: Test with curl on localhost
6. **Step 6**: Update README.md
7. **Step 7**: Update CHANGELOG.md
8. **Step 8**: Move Issue #10 to completed in TODO.md
9. **Step 9**: Delete this implementation plan
10. **Step 10**: Commit all changes

## 10. Testing Strategy

### Manual Testing:

```bash
# Start web-demo
go run examples/web-demo/main.go

# Test localhost (should have relaxed CSP)
curl -H "Host: localhost:8181" -I http://localhost:8181/
# Should see: script-src 'self' 'unsafe-inline' 'unsafe-eval'
# Should NOT see: Strict-Transport-Security

# Test production simulation (strict CSP)
curl -H "Host: example.com" -I http://localhost:8181/
# Should see: script-src 'self' (no unsafe-inline)
# Should NOT see: Strict-Transport-Security (HTTP)

# Test HTTPS production simulation
curl -H "Host: example.com" -H "X-Forwarded-Proto: https" -I http://localhost:8181/
# Should see: Strict-Transport-Security header
```

### Automated Testing:

```bash
go test -v -run TestSecurity
```

## 11. Expected Impact

### Security Benefits:
✅ **All library users get security headers** automatically
✅ **Prevents XSS attacks** with CSP
✅ **Prevents clickjacking** with X-Frame-Options
✅ **Prevents MIME-sniffing** with X-Content-Type-Options
✅ **Enforces HTTPS** with HSTS (production only)

### Developer Experience:
✅ **No configuration needed** - works automatically
✅ **Localhost-friendly** - no CSP violations during development
✅ **Production-ready** - strict headers for deployed apps
✅ **Reverse proxy compatible** - detects HTTPS correctly

### Library Quality:
✅ **Industry standard** - follows OWASP recommendations
✅ **Well-tested** - comprehensive test suite
✅ **Well-documented** - clear usage examples
✅ **Easy to use** - single line of code to enable

## 12. Notes

- **Request-based detection** is superior to config-based because it works correctly behind reverse proxies and in any deployment scenario
- **'unsafe-eval'** is included for localhost to support development tools and hot-reloading
- **HSTS on localhost** would be problematic as it would prevent HTTP access for development
- **Library-level implementation** means users don't need to copy-paste security code
