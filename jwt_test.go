package bskyoauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Helper function to create a test ECDSA key pair
func createTestECDSAKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// Helper function to create a test JWT token
func createTestToken(key *ecdsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	// Add kid header
	token.Header["kid"] = "test-key-1"

	return token.SignedString(key)
}

// Helper function to create a mock JWKS server
func createMockJWKSServer(pubKey *ecdsa.PublicKey) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Encode public key coordinates
		xBytes := pubKey.X.Bytes()
		yBytes := pubKey.Y.Bytes()

		// Pad to 32 bytes for P-256
		if len(xBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(xBytes):], xBytes)
			xBytes = padded
		}
		if len(yBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(yBytes):], yBytes)
			yBytes = padded
		}

		x := base64.RawURLEncoding.EncodeToString(xBytes)
		y := base64.RawURLEncoding.EncodeToString(yBytes)

		jwks := jwksResponse{
			Keys: []jwk{
				{
					Kty: "EC",
					Use: "sig",
					Crv: "P-256",
					Kid: "test-key-1",
					X:   x,
					Y:   y,
					Alg: "ES256",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
}

func TestValidateAccessToken_ValidToken(t *testing.T) {
	// Create test key
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	// Create mock JWKS server
	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	// Create valid token
	claims := jwt.MapClaims{
		"iss": "https://test.example.com",
		"sub": "did:plc:test123",
		"aud": "test-client",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	tokenString, err := createTestToken(privKey, claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Validate token
	validatedToken, err := validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err != nil {
		t.Errorf("Expected valid token to pass validation, got error: %v", err)
	}

	if validatedToken == nil {
		t.Error("Expected non-nil validated token")
	}

	// Verify claims
	validatedClaims, ok := validatedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Expected MapClaims")
	}

	if validatedClaims["sub"] != "did:plc:test123" {
		t.Errorf("Expected sub claim 'did:plc:test123', got %v", validatedClaims["sub"])
	}
}

func TestValidateAccessToken_ExpiredToken(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	// Create expired token
	claims := jwt.MapClaims{
		"iss": "https://test.example.com",
		"sub": "did:plc:test123",
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	}

	tokenString, err := createTestToken(privKey, claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Validate token - should fail
	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err == nil {
		t.Error("Expected expired token to fail validation")
	}

	// Check for specific error
	if err != nil && !contains(err.Error(), "expired") && !contains(err.Error(), "exp") {
		t.Errorf("Expected error to mention expiration, got: %v", err)
	}
}

func TestValidateAccessToken_InvalidSignature(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	// Create token with one key
	claims := jwt.MapClaims{
		"iss": "https://test.example.com",
		"sub": "did:plc:test123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	tokenString, err := createTestToken(privKey, claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Create JWKS server with different key
	differentKey, _ := createTestECDSAKey()
	server := createMockJWKSServer(&differentKey.PublicKey)
	defer server.Close()

	// Validate token - should fail due to signature mismatch
	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err == nil {
		t.Error("Expected token with invalid signature to fail validation")
	}
}

func TestValidateAccessToken_WrongIssuer(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	// Create token with different issuer
	claims := jwt.MapClaims{
		"iss": "https://wrong.example.com",
		"sub": "did:plc:test123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	tokenString, err := createTestToken(privKey, claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Validate with different expected issuer
	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err == nil {
		t.Error("Expected token with wrong issuer to fail validation")
	}

	if err != nil && !contains(err.Error(), "issuer") {
		t.Errorf("Expected error to mention issuer mismatch, got: %v", err)
	}
}

func TestValidateAccessToken_MissingClaims(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	testCases := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{
			name: "Missing sub claim",
			claims: jwt.MapClaims{
				"iss": "https://test.example.com",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
		},
		{
			name: "Missing iss claim",
			claims: jwt.MapClaims{
				"sub": "did:plc:test123",
				"exp": time.Now().Add(1 * time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
		},
		{
			name: "Missing exp claim",
			claims: jwt.MapClaims{
				"iss": "https://test.example.com",
				"sub": "did:plc:test123",
				"iat": time.Now().Unix(),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, err := createTestToken(privKey, tc.claims)
			if err != nil {
				t.Fatalf("Failed to create test token: %v", err)
			}

			_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
			if err == nil {
				t.Errorf("Expected token with %s to fail validation", tc.name)
			}
		})
	}
}

func TestValidateAccessToken_FutureIssuedAt(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	// Create token with future iat (more than 5 min clock skew)
	claims := jwt.MapClaims{
		"iss": "https://test.example.com",
		"sub": "did:plc:test123",
		"exp": time.Now().Add(2 * time.Hour).Unix(),
		"iat": time.Now().Add(10 * time.Minute).Unix(), // 10 minutes in future
	}

	tokenString, err := createTestToken(privKey, claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err == nil {
		t.Error("Expected token with future iat to fail validation")
	}
}

func TestValidateAccessToken_EmptyToken(t *testing.T) {
	_, err := validateAccessToken("", "https://test.example.com", "https://jwks.example.com")
	if err == nil {
		t.Error("Expected empty token to fail validation")
	}

	if err != nil && !contains(err.Error(), "empty") {
		t.Errorf("Expected error to mention empty token, got: %v", err)
	}
}

func TestValidateAccessToken_EmptyJWKSURI(t *testing.T) {
	_, err := validateAccessToken("test.token.string", "https://test.example.com", "")
	if err == nil {
		t.Error("Expected empty JWKS URI to fail validation")
	}

	if err != nil && !contains(err.Error(), "JWKS") {
		t.Errorf("Expected error to mention JWKS URI, got: %v", err)
	}
}

func TestJWKSCache_Caching(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		xBytes := privKey.PublicKey.X.Bytes()
		yBytes := privKey.PublicKey.Y.Bytes()

		if len(xBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(xBytes):], xBytes)
			xBytes = padded
		}
		if len(yBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(yBytes):], yBytes)
			yBytes = padded
		}

		x := base64.RawURLEncoding.EncodeToString(xBytes)
		y := base64.RawURLEncoding.EncodeToString(yBytes)

		jwks := jwksResponse{
			Keys: []jwk{
				{
					Kty: "EC",
					Use: "sig",
					Crv: "P-256",
					Kid: "test-key-1",
					X:   x,
					Y:   y,
					Alg: "ES256",
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	claims := jwt.MapClaims{
		"iss": "https://test.example.com",
		"sub": "did:plc:test123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	tokenString, err := createTestToken(privKey, claims)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// First validation - should fetch JWKS
	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err != nil {
		t.Fatalf("First validation failed: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("Expected 1 JWKS request, got %d", requestCount)
	}

	// Second validation - should use cache
	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err != nil {
		t.Fatalf("Second validation failed: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("Expected cache to be used (1 total request), got %d requests", requestCount)
	}
}

func TestJWKSCache_Expiration(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	// Create cache with very short TTL
	cache := NewJWKSCache(100 * time.Millisecond)

	// Fetch JWKS
	err = cache.fetchJWKS(server.URL)
	if err != nil {
		t.Fatalf("Failed to fetch JWKS: %v", err)
	}

	// Should not be expired immediately
	if cache.isExpired() {
		t.Error("Cache should not be expired immediately after fetch")
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should now be expired
	if !cache.isExpired() {
		t.Error("Cache should be expired after TTL")
	}
}

func TestJWKSCache_KeyRetrieval(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	cache := NewJWKSCache(1 * time.Hour)

	// Fetch JWKS
	err = cache.fetchJWKS(server.URL)
	if err != nil {
		t.Fatalf("Failed to fetch JWKS: %v", err)
	}

	// Try to get existing key
	key, exists := cache.getKey("test-key-1")
	if !exists {
		t.Error("Expected key 'test-key-1' to exist in cache")
	}

	if key == nil {
		t.Error("Expected non-nil key")
	}

	// Try to get non-existent key
	_, exists = cache.getKey("non-existent-key")
	if exists {
		t.Error("Expected non-existent key to not be found")
	}
}

func TestValidateAccessToken_WrongAlgorithm(t *testing.T) {
	// Create an HS256 token (HMAC, not ECDSA)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "https://test.example.com",
		"sub": "did:plc:test123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	token.Header["kid"] = "test-key-1"
	tokenString, _ := token.SignedString([]byte("secret"))

	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	// Should fail due to algorithm mismatch
	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err == nil {
		t.Error("Expected token with wrong algorithm to fail validation")
	}
}

func TestValidateAccessToken_MissingKid(t *testing.T) {
	privKey, err := createTestECDSAKey()
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	// Create token without kid header
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://test.example.com",
		"sub": "did:plc:test123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
		"iat": time.Now().Unix(),
	})

	// Don't set kid header
	tokenString, _ := token.SignedString(privKey)

	server := createMockJWKSServer(&privKey.PublicKey)
	defer server.Close()

	// Should fail due to missing kid
	_, err = validateAccessToken(tokenString, "https://test.example.com", server.URL)
	if err == nil {
		t.Error("Expected token without kid to fail validation")
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
