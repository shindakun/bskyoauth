# Implementation Plan for Issue #10: Missing Security Headers

Based on analysis of the web-demo application and security best practices, here's a comprehensive plan to implement security headers middleware.

## Overview
Add comprehensive security headers middleware to protect against XSS, clickjacking, MIME-type sniffing, and enforce HTTPS. The implementation should be **production-focused** with automatic detection of development vs production environments.

## 1. Create Security Headers Middleware (`examples/web-demo/security.go`)

**Purpose**: Centralized security headers middleware that adapts to environment (development vs production).

**Key Features**:
- Environment detection (localhost vs production)
- HTTPS-aware headers (HSTS only for HTTPS)
- Configurable CSP policy
- Automatic header application to all responses

### Security Headers to Implement:

#### a) Content-Security-Policy (CSP)
**Purpose**: Prevents XSS attacks by controlling resource loading

**Development Policy** (localhost):
```
default-src 'self';
script-src 'self' 'unsafe-inline';
style-src 'self' 'unsafe-inline';
img-src 'self' data:;
connect-src 'self';
form-action 'self';
```

**Production Policy**:
```
default-src 'self';
script-src 'self';
style-src 'self';
img-src 'self' data:;
connect-src 'self';
form-action 'self';
frame-ancestors 'none';
base-uri 'self';
```

**Rationale**:
- Development allows `'unsafe-inline'` for quick prototyping
- Production removes `'unsafe-inline'` for maximum security
- `frame-ancestors 'none'` prevents clickjacking
- `data:` for inline images (common in modern apps)

#### b) X-Frame-Options
**Value**: `DENY`

**Purpose**: Prevents clickjacking attacks by blocking iframe embedding

**Note**: Redundant with CSP `frame-ancestors` but provides defense-in-depth for older browsers

#### c) X-Content-Type-Options
**Value**: `nosniff`

**Purpose**: Prevents MIME-type sniffing attacks

**Security Impact**: Browsers will respect Content-Type headers, preventing execution of JavaScript disguised as images

#### d) Strict-Transport-Security (HSTS)
**Value**: `max-age=31536000; includeSubDomains; preload`

**Purpose**: Enforces HTTPS for all future requests

**Conditions**:
- **ONLY set for HTTPS connections** (setting on HTTP causes errors)
- Not set for localhost development
- max-age=31536000 (1 year) for production
- includeSubDomains protects all subdomains
- preload allows inclusion in browser HSTS preload lists

#### e) X-XSS-Protection (Legacy)
**Value**: `1; mode=block`

**Purpose**: Enables browser XSS filters (legacy browsers)

**Note**: Modern browsers rely on CSP, but this provides defense-in-depth

#### f) Referrer-Policy
**Value**: `strict-origin-when-cross-origin`

**Purpose**: Controls referrer information sent with requests

**Security Impact**: Prevents leaking sensitive URLs to third parties

### Implementation Structure:

```go
// SecurityHeadersConfig holds configuration for security headers middleware
type SecurityHeadersConfig struct {
    IsProduction bool
    IsHTTPS      bool
}

// SecurityHeadersMiddleware returns HTTP middleware that sets security headers
func SecurityHeadersMiddleware(config SecurityHeadersConfig) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Set headers based on environment
            setSecurityHeaders(w, config)
            next.ServeHTTP(w, r)
        })
    }
}

// setSecurityHeaders applies appropriate security headers
func setSecurityHeaders(w http.ResponseWriter, config SecurityHeadersConfig) {
    // Always set these headers
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-XSS-Protection", "1; mode=block")
    w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

    // Set CSP based on environment
    if config.IsProduction {
        w.Header().Set("Content-Security-Policy", getProductionCSP())
    } else {
        w.Header().Set("Content-Security-Policy", getDevelopmentCSP())
    }

    // Only set HSTS for HTTPS in production
    if config.IsHTTPS && config.IsProduction {
        w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
    }
}

func getDevelopmentCSP() string {
    return "default-src 'self'; " +
           "script-src 'self' 'unsafe-inline'; " +
           "style-src 'self' 'unsafe-inline'; " +
           "img-src 'self' data:; " +
           "connect-src 'self'; " +
           "form-action 'self'"
}

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

## 2. Update `examples/web-demo/main.go`

### a) Add Environment Detection

```go
func main() {
    baseURL := os.Getenv("BASE_URL")
    if baseURL == "" {
        baseURL = "http://localhost:8181"
    }

    // Detect environment
    isProduction := !strings.Contains(baseURL, "localhost") && !strings.Contains(baseURL, "127.0.0.1")
    isHTTPS := strings.HasPrefix(baseURL, "https://")

    // Log environment detection
    if isProduction {
        log.Println("✓ Running in PRODUCTION mode")
        log.Println("✓ Security headers: PRODUCTION policy (strict CSP, no unsafe-inline)")
    } else {
        log.Println("✓ Running in DEVELOPMENT mode")
        log.Println("✓ Security headers: DEVELOPMENT policy (allows unsafe-inline)")
    }

    // ... existing security check ...
```

### b) Apply Security Headers Middleware

**Option 1: Wrap http.DefaultServeMux**
```go
    // Create security headers middleware
    securityConfig := SecurityHeadersConfig{
        IsProduction: isProduction,
        IsHTTPS:      isHTTPS,
    }
    securityMiddleware := SecurityHeadersMiddleware(securityConfig)

    // Set up HTTP handlers
    mux := http.NewServeMux()
    mux.HandleFunc("/", homeHandler(client))
    mux.HandleFunc("/client-metadata.json", client.ClientMetadataHandler())
    mux.HandleFunc("/login", authLimiter.Middleware(loginHandler(client)))
    // ... other handlers ...

    // Wrap entire mux with security headers
    handler := securityMiddleware(mux)

    log.Fatal(http.ListenAndServe(":8181", handler))
```

**Option 2: Combine with existing middleware chain**
```go
    // Chain middleware: security headers -> rate limiting -> handler
    http.HandleFunc("/login",
        securityMiddleware(
            authLimiter.Middleware(loginHandler(client))
        )
    )
```

**Recommendation**: Use Option 1 (wrap entire mux) for cleaner code and guaranteed header coverage.

### c) Add Security Headers Status Logging

```go
    log.Println("✓ Security headers enabled:")
    log.Println("  - X-Frame-Options: DENY")
    log.Println("  - X-Content-Type-Options: nosniff")
    log.Println("  - Content-Security-Policy:", getCSPForEnvironment(isProduction))
    if isHTTPS && isProduction {
        log.Println("  - Strict-Transport-Security: enabled (HSTS)")
    } else if !isProduction {
        log.Println("  - Strict-Transport-Security: disabled (development mode)")
    } else {
        log.Println("  - Strict-Transport-Security: disabled (HTTP, use HTTPS for HSTS)")
    }
```

## 3. Create Test Suite (`examples/web-demo/security_test.go`)

**Test cases** (minimum 15 tests):

### Environment Detection Tests (3 tests)
- Test localhost detection (should be development)
- Test production URL detection (should be production)
- Test HTTPS detection

### CSP Policy Tests (4 tests)
- Test development CSP includes 'unsafe-inline'
- Test production CSP excludes 'unsafe-inline'
- Test production CSP includes 'frame-ancestors none'
- Test CSP includes 'self' for all sources

### HSTS Tests (4 tests)
- Test HSTS set for HTTPS in production
- Test HSTS NOT set for HTTP
- Test HSTS NOT set for localhost
- Test HSTS value correct (max-age, includeSubDomains, preload)

### Header Application Tests (4 tests)
- Test all headers present in production
- Test all headers present in development
- Test X-Frame-Options is DENY
- Test X-Content-Type-Options is nosniff

## 4. Update Documentation

### a) Add to README.md Security Section

```markdown
### Security Headers

The web-demo example includes comprehensive security headers middleware that automatically adapts to your environment:

#### Automatic Environment Detection

- **Development Mode** (localhost/127.0.0.1): Relaxed CSP policy with `'unsafe-inline'` for easier prototyping
- **Production Mode** (public domains): Strict CSP policy without `'unsafe-inline'`

#### Headers Applied

| Header | Value | Purpose |
|--------|-------|---------|
| Content-Security-Policy | Environment-specific | Prevents XSS attacks |
| X-Frame-Options | DENY | Prevents clickjacking |
| X-Content-Type-Options | nosniff | Prevents MIME-sniffing |
| Strict-Transport-Security | max-age=31536000 (HTTPS only) | Enforces HTTPS |
| X-XSS-Protection | 1; mode=block | Legacy XSS protection |
| Referrer-Policy | strict-origin-when-cross-origin | Controls referrer leakage |

#### HSTS (HTTP Strict Transport Security)

HSTS is **automatically enabled** when:
- Running on HTTPS (`https://` in BASE_URL)
- Running in production mode (not localhost)

HSTS is **disabled** for:
- HTTP connections (would cause errors)
- Localhost development (allows HTTP testing)

#### Custom CSP Configuration

If your application needs different CSP policies (e.g., loading external resources), modify the CSP functions in `examples/web-demo/security.go`:

```go
func getProductionCSP() string {
    return "default-src 'self'; " +
           "script-src 'self' https://trusted-cdn.com; " + // Add trusted sources
           "style-src 'self' 'unsafe-inline'; " +          // Allow inline styles if needed
           // ... other directives
}
```

#### Testing Security Headers

You can verify security headers are applied using curl:

```bash
curl -I http://localhost:8181/
```

Look for the security headers in the response.
```

### b) Update CHANGELOG.md

```markdown
### Added
- **SECURITY**: Added comprehensive security headers middleware (security.go)
  - Content-Security-Policy with environment-aware policies
  - X-Frame-Options: DENY (prevents clickjacking)
  - X-Content-Type-Options: nosniff (prevents MIME-sniffing)
  - Strict-Transport-Security (HSTS) for HTTPS production deployments
  - X-XSS-Protection for legacy browser support
  - Referrer-Policy to prevent information leakage
- Automatic environment detection (development vs production)
- Security headers test suite with 15 test cases

### Changed
- **SECURITY**: Web-demo now applies security headers to all responses
- **SECURITY**: CSP policy adapts to environment (strict in production, relaxed in development)
- **SECURITY**: HSTS automatically enabled for HTTPS production deployments
- Security status logging shows which headers are active
```

## 5. Implementation Order

1. **Step 1**: Create `examples/web-demo/security.go` with middleware implementation
2. **Step 2**: Update `examples/web-demo/main.go` to use security middleware
3. **Step 3**: Add environment detection and logging
4. **Step 4**: Create `examples/web-demo/security_test.go` with comprehensive tests
5. **Step 5**: Test locally with both HTTP and HTTPS configurations
6. **Step 6**: Update README.md with security headers documentation
7. **Step 7**: Update CHANGELOG.md
8. **Step 8**: Update TODO.md to mark issue #10 as completed
9. **Step 9**: Delete IMPLEMENTATION_PLAN_ISSUE10.md
10. **Step 10**: Commit changes

## 6. Expected Impact

### Security Benefits:
✅ **Prevents XSS attacks**: CSP blocks unauthorized script execution
✅ **Prevents clickjacking**: X-Frame-Options and CSP frame-ancestors
✅ **Prevents MIME-sniffing attacks**: X-Content-Type-Options
✅ **Enforces HTTPS**: HSTS ensures all future requests use HTTPS
✅ **Defense-in-depth**: Multiple overlapping protections
✅ **Browser security features**: Enables built-in browser protections

### Development Experience:
✅ **No production interference**: Automatic environment detection
✅ **Localhost works normally**: No HSTS on local development
✅ **Easy prototyping**: Development mode allows inline scripts/styles
✅ **Clear logging**: Shows which security mode is active
✅ **Zero configuration**: Works out of the box based on BASE_URL

### Production Readiness:
✅ **Strict CSP**: No unsafe-inline in production
✅ **HSTS enabled**: Enforces HTTPS automatically
✅ **Comprehensive coverage**: All major security headers
✅ **Industry standard**: Follows OWASP recommendations

## 7. Testing Strategy

### Manual Testing:

**Development Mode**:
```bash
# Start web-demo in development mode
BASE_URL=http://localhost:8181 go run examples/web-demo/*.go

# Verify headers
curl -I http://localhost:8181/

# Should see:
# - CSP with 'unsafe-inline'
# - No HSTS header
# - X-Frame-Options: DENY
# - X-Content-Type-Options: nosniff
```

**Production Mode (HTTP)**:
```bash
# Start with production URL (HTTP)
BASE_URL=http://example.com go run examples/web-demo/*.go

# Verify headers
curl -I http://localhost:8181/

# Should see:
# - Strict CSP without 'unsafe-inline'
# - No HSTS (HTTP mode)
# - All other headers present
```

**Production Mode (HTTPS)**:
```bash
# Start with production URL (HTTPS)
BASE_URL=https://example.com go run examples/web-demo/*.go

# Verify headers
curl -I http://localhost:8181/

# Should see:
# - Strict CSP without 'unsafe-inline'
# - HSTS header present
# - All other headers present
```

### Automated Testing:
- Run test suite: `go test ./examples/web-demo -v`
- Verify all 15+ tests pass
- Check coverage for security.go

## 8. Browser Compatibility

All security headers are widely supported:

| Header | Chrome | Firefox | Safari | Edge |
|--------|--------|---------|--------|------|
| CSP | ✅ All | ✅ All | ✅ All | ✅ All |
| X-Frame-Options | ✅ All | ✅ All | ✅ All | ✅ All |
| X-Content-Type-Options | ✅ All | ✅ All | ✅ All | ✅ All |
| HSTS | ✅ All | ✅ All | ✅ All | ✅ All |

**Note**: Older browsers may not support all CSP directives, but the headers won't cause errors.

## 9. Notes

- **HSTS is powerful**: Once enabled, browsers will refuse HTTP connections for the max-age duration (1 year)
- **Test carefully**: Test HSTS behavior before deploying to production with a shorter max-age first
- **CSP can break things**: If your app loads external resources, you'll need to whitelist them in CSP
- **Development convenience**: 'unsafe-inline' in development mode allows quick prototyping without CSP violations
- **Environment auto-detection**: Based on BASE_URL containing 'localhost' or '127.0.0.1'
- **Middleware composition**: Security headers are applied at the top level, before rate limiting

## 10. Future Enhancements

**Not included in this implementation** (but could be added later):
- CSP violation reporting endpoint
- Permissions-Policy header (formerly Feature-Policy)
- Custom CSP policies per route
- CSP nonce generation for inline scripts
- Subresource Integrity (SRI) for external resources

These are advanced features better suited for production applications with specific needs.
