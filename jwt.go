package bskyoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// DefaultJWKSCacheTTL is the default time-to-live for cached JWKS keys.
	DefaultJWKSCacheTTL = 1 * time.Hour

	// DefaultJWKSTimeout is the default timeout for JWKS HTTP requests.
	DefaultJWKSTimeout = 30 * time.Second
)

var (
	// ErrInvalidToken indicates the access token is invalid.
	ErrInvalidToken = errors.New("invalid access token")

	// ErrTokenExpired indicates the access token has expired.
	ErrTokenExpired = errors.New("access token expired")

	// ErrInvalidSignature indicates the token signature is invalid.
	ErrInvalidSignature = errors.New("invalid token signature")

	// ErrInvalidIssuer indicates the token issuer doesn't match expected value.
	ErrInvalidIssuer = errors.New("token issuer mismatch")

	// ErrJWKSFetch indicates failure to fetch JWKS from the authorization server.
	ErrJWKSFetch = errors.New("failed to fetch JWKS")

	// ErrInvalidAlgorithm indicates the token uses an unsupported algorithm.
	ErrInvalidAlgorithm = errors.New("invalid token algorithm")

	// ErrMissingClaims indicates required claims are missing from the token.
	ErrMissingClaims = errors.New("missing required token claims")
)

// JWKSCache caches JSON Web Key Sets to minimize repeated fetches.
type JWKSCache struct {
	keys      map[string]*ecdsa.PublicKey // kid -> public key
	fetchedAt time.Time
	ttl       time.Duration
	mu        sync.RWMutex
}

// NewJWKSCache creates a new JWKS cache with the specified TTL.
func NewJWKSCache(ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		keys: make(map[string]*ecdsa.PublicKey),
		ttl:  ttl,
	}
}

// jwksResponse represents the JSON Web Key Set response structure.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// jwk represents a single JSON Web Key.
type jwk struct {
	Kty string `json:"kty"` // Key Type (e.g., "EC")
	Use string `json:"use"` // Public Key Use (e.g., "sig")
	Crv string `json:"crv"` // Curve (e.g., "P-256")
	Kid string `json:"kid"` // Key ID
	X   string `json:"x"`   // X coordinate (base64url)
	Y   string `json:"y"`   // Y coordinate (base64url)
	Alg string `json:"alg"` // Algorithm (e.g., "ES256")
}

// fetchJWKS fetches the JWKS from the specified URI and updates the cache.
func (c *JWKSCache) fetchJWKS(jwksURI string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if cache is still valid (double-check after acquiring lock)
	if time.Since(c.fetchedAt) < c.ttl {
		return nil
	}

	client := &http.Client{
		Timeout: DefaultJWKSTimeout,
	}

	resp, err := client.Get(jwksURI)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%w: status %d, body: %s", ErrJWKSFetch, resp.StatusCode, string(body))
	}

	var jwksResp jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwksResp); err != nil {
		return fmt.Errorf("%w: failed to decode JWKS: %v", ErrJWKSFetch, err)
	}

	// Parse and store keys
	newKeys := make(map[string]*ecdsa.PublicKey)
	for _, key := range jwksResp.Keys {
		if key.Kty != "EC" || key.Crv != "P-256" {
			// Skip non-ECDSA P-256 keys
			continue
		}

		pubKey, err := parseECDSAPublicKey(key)
		if err != nil {
			// Log error but don't fail - other keys might be valid
			continue
		}

		newKeys[key.Kid] = pubKey
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("%w: no valid ECDSA P-256 keys found in JWKS", ErrJWKSFetch)
	}

	c.keys = newKeys
	c.fetchedAt = time.Now()

	return nil
}

// getKey retrieves a public key from the cache by key ID.
func (c *JWKSCache) getKey(kid string) (*ecdsa.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key, exists := c.keys[kid]
	return key, exists
}

// isExpired checks if the cache has exceeded its TTL.
func (c *JWKSCache) isExpired() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return time.Since(c.fetchedAt) >= c.ttl
}

// parseECDSAPublicKey parses a JWK into an ECDSA public key.
func parseECDSAPublicKey(key jwk) (*ecdsa.PublicKey, error) {
	// Decode base64url coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(key.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode X coordinate: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(key.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Y coordinate: %w", err)
	}

	// Create ECDSA public key with P-256 curve
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// Global JWKS cache (one per auth server)
var (
	globalJWKSCaches   = make(map[string]*JWKSCache)
	globalJWKSCachesMu sync.RWMutex
)

// getOrCreateJWKSCache retrieves or creates a JWKS cache for the given URI.
func getOrCreateJWKSCache(jwksURI string) *JWKSCache {
	globalJWKSCachesMu.RLock()
	cache, exists := globalJWKSCaches[jwksURI]
	globalJWKSCachesMu.RUnlock()

	if exists {
		return cache
	}

	globalJWKSCachesMu.Lock()
	defer globalJWKSCachesMu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists := globalJWKSCaches[jwksURI]; exists {
		return cache
	}

	cache = NewJWKSCache(DefaultJWKSCacheTTL)
	globalJWKSCaches[jwksURI] = cache
	return cache
}

// validateAccessToken validates an access token JWT including signature verification.
func validateAccessToken(tokenString, expectedIssuer, jwksURI string) (*jwt.Token, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}

	if jwksURI == "" {
		return nil, fmt.Errorf("%w: empty JWKS URI", ErrJWKSFetch)
	}

	// Get or create JWKS cache for this auth server
	cache := getOrCreateJWKSCache(jwksURI)

	// Fetch JWKS if cache is expired
	if cache.isExpired() {
		if err := cache.fetchJWKS(jwksURI); err != nil {
			return nil, err
		}
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate algorithm
		if token.Method.Alg() != "ES256" {
			return nil, fmt.Errorf("%w: expected ES256, got %s", ErrInvalidAlgorithm, token.Method.Alg())
		}

		// Get key ID from token header
		kid, ok := token.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("%w: missing kid in token header", ErrInvalidToken)
		}

		// Retrieve public key from cache
		pubKey, exists := cache.getKey(kid)
		if !exists {
			// Key not in cache - try refreshing JWKS
			if err := cache.fetchJWKS(jwksURI); err != nil {
				return nil, err
			}

			// Try again after refresh
			pubKey, exists = cache.getKey(kid)
			if !exists {
				return nil, fmt.Errorf("%w: key ID %s not found in JWKS", ErrInvalidToken, kid)
			}
		}

		return pubKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", ErrTokenExpired, err)
		}
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			return nil, fmt.Errorf("%w: %v", ErrInvalidSignature, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("%w: token validation failed", ErrInvalidToken)
	}

	// Extract and validate claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("%w: invalid claims format", ErrInvalidToken)
	}

	// Validate required claims
	if err := validateTokenClaims(claims, expectedIssuer); err != nil {
		return nil, err
	}

	return token, nil
}

// validateTokenClaims validates required JWT claims.
func validateTokenClaims(claims jwt.MapClaims, expectedIssuer string) error {
	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok || iss == "" {
		return fmt.Errorf("%w: missing iss claim", ErrMissingClaims)
	}
	if iss != expectedIssuer {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidIssuer, expectedIssuer, iss)
	}

	// Validate subject (DID)
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return fmt.Errorf("%w: missing sub claim", ErrMissingClaims)
	}

	// Validate expiration (checked by jwt.Parse, but verify it exists)
	if _, ok := claims["exp"]; !ok {
		return fmt.Errorf("%w: missing exp claim", ErrMissingClaims)
	}

	// Validate issued at (should be in the past)
	if iat, ok := claims["iat"].(float64); ok {
		issuedAt := time.Unix(int64(iat), 0)
		if issuedAt.After(time.Now().Add(5 * time.Minute)) {
			// Allow 5 minute clock skew
			return fmt.Errorf("%w: iat claim is in the future", ErrInvalidToken)
		}
	}

	return nil
}
