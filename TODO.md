# Security Improvement Plan - bskyoauth

## Executive Summary
This security audit identified multiple areas for improvement in the bskyoauth library. While the implementation demonstrates good security practices with OAuth 2.0, PKCE, and DPoP, there are several vulnerabilities and improvements needed to enhance security posture.

---

## Critical Priority Issues

*No critical priority issues remain.*

---

## Medium Priority Issues

*No medium priority issues remain.*

---

## Low Priority / Best Practices

### 16. DPoP Key Storage Considerations
**File:** [types.go:19-20](types.go#L19-L20)

**Issue:** DPoP private keys stored in memory only. Lost on application restart.

**Recommendation:**
- Document key lifecycle expectations
- Consider encrypted key persistence for long-lived sessions
- Provide guidance on key rotation
- Note: Current design may be intentional for ephemeral keys

---

### 17. Missing Audit Trail
**Issue:** No audit log for sensitive operations.

**Recommendation:**
- Implement audit logging for:
  - Authentication attempts
  - Session creation/deletion
  - Post creation/deletion
  - Record modifications
- Include user DID, timestamp, action, result

---

### 18. Environment Configuration
**File:** [examples/web-demo/main.go:14-17](examples/web-demo/main.go#L14-L17)

**Issue:** Limited configuration options via environment variables.

**Recommendation:**
- Add configuration for:
  - Session timeout
  - Cookie security settings
  - Rate limiting parameters
  - Logging level
- Consider configuration file support
- Validate configuration on startup

---

## Implementation Priority Order

1. **Immediate (Critical):**
   - Issue #4: Add HTTPS documentation and warnings
   - Issue #7: Implement JWT validation
   - Issue #1: Enhance cookie security

2. **Short-term (High):**
   - Issue #2: Session store expiration
   - Issue #3: OAuth state expiration
   - Issue #8: Rate limiting
   - Issue #5: CSRF enhancement

3. **Medium-term (Medium):**
   - Issue #9: Input validation
   - Issue #10: Security headers
   - Issue #11: Logging improvements
   - Issue #12: Refresh token support

4. **Long-term (Low):**
   - Issues #13-18: Best practices and maintenance items

---

## Testing Recommendations

After implementing fixes, test the following scenarios:

1. **Session Security:**
   - Verify session expiration works correctly
   - Test session hijacking resistance with Secure flag
   - Validate CSRF protection

2. **Token Security:**
   - Test JWT validation with manipulated tokens
   - Verify token expiration handling
   - Test refresh token flow

3. **Rate Limiting:**
   - Verify rate limits are enforced
   - Test both IP-based and user-based limits
   - Ensure legitimate users aren't impacted

4. **Input Validation:**
   - Fuzz test all user inputs
   - Test boundary conditions (max lengths)
   - Verify sanitization prevents injection

---

## Security Best Practices for Users

Document these recommendations for library users:

1. **Production Deployment:**
   - Always use HTTPS (TLS 1.2+)
   - Use secure session store (Redis, database)
   - Enable all cookie security flags
   - Implement rate limiting

2. **Monitoring:**
   - Monitor failed authentication attempts
   - Alert on unusual session patterns
   - Track API usage and errors

3. **Updates:**
   - Keep library and dependencies updated
   - Subscribe to security advisories
   - Test updates in staging first

4. **Configuration:**
   - Use strong session IDs (current implementation is good)
   - Set appropriate session timeouts
   - Configure logging appropriately
   - Review security headers for your use case

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Go Security Best Practices](https://go.dev/doc/security/best-practices)
- [DPoP Specification RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)

---

## Notes

- This audit assumes the library is used in production web applications
- Some recommendations may require breaking API changes - consider versioning
- Security is an ongoing process - regular audits recommended
- Consider engaging professional security audit for production use

Generated: 2025-10-27

---

## NOT APPLICABLE ISSUES

These issues were identified during the security audit but are not applicable due to specification requirements or architectural decisions.

### 7. JWT Token Validation ⚠️ **NOT APPLICABLE**
**File:** [oauth.go:292-315](oauth.go#L292-L315)

**Status:** NOT REQUIRED per AT Protocol OAuth Specification

**Original Issue:** Access token JWT is parsed but not validated:
- No signature verification
- No expiration check
- No issuer validation
- Trusts token claims without verification

**Resolution:**
Per the [AT Protocol OAuth specification](https://atproto.com/specs/oauth), **access tokens are intentionally opaque from the client's perspective**. The spec states:

> "Access tokens are used to authorize client requests to the account's PDS ('Resource Server'). From the standpoint of the client they are opaque, but they are often signed JWTs including an expiration time."

**Why JWT validation is NOT performed:**
1. **Spec Compliance**: AT Protocol explicitly requires clients to treat tokens as opaque
2. **Server-Side Validation**: Token validation is the responsibility of the Resource Server (PDS), not the client
3. **DPoP Security**: Token security is provided through DPoP (Demonstrating Proof-of-Possession) binding
4. **Automatic Validation**: Tokens are validated by the PDS on first use anyway

**Current Implementation:**
- Access tokens treated as opaque strings per spec
- JWT parsing only used to extract DID for session management
- Fallback to OAuth state DID if token parsing fails
- No signature verification or claim validation performed

**Available Resources:**
- JWT verification code is in internal/jwt package for internal use only
- Not exposed in public API per AT Protocol OAuth specification

**Impact:** This is the CORRECT behavior per AT Protocol specification. Client-side JWT validation would be redundant and against spec.

---

## COMPLETED ISSUES

All completed issues have been archived to [COMPLETED_ISSUES.md](COMPLETED_ISSUES.md) to keep this TODO focused on active work.

For implementation details, see [CHANGELOG.md](CHANGELOG.md).

