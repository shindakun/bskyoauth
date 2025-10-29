package dpop

import (
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// TestGenerateDPoPKey verifies DPoP key generation.
func TestGenerateDPoPKey(t *testing.T) {
	key, err := GenerateDPoPKey()
	if err != nil {
		t.Fatalf("GenerateDPoPKey failed: %v", err)
	}

	if key == nil {
		t.Fatal("Generated key is nil")
	}

	if key.Curve != elliptic.P256() {
		t.Error("Key should use P-256 curve")
	}

	if key.PublicKey.X == nil || key.PublicKey.Y == nil {
		t.Error("Public key coordinates are nil")
	}

	if key.D == nil {
		t.Error("Private key component is nil")
	}
}

// TestGenerateDPoPKeyUniqueness verifies keys are unique.
func TestGenerateDPoPKeyUniqueness(t *testing.T) {
	key1, _ := GenerateDPoPKey()
	key2, _ := GenerateDPoPKey()

	// Keys should be different
	if key1.D.Cmp(key2.D) == 0 {
		t.Error("Generated keys are not unique")
	}

	if key1.PublicKey.X.Cmp(key2.PublicKey.X) == 0 && key1.PublicKey.Y.Cmp(key2.PublicKey.Y) == 0 {
		t.Error("Public keys are not unique")
	}
}

// TestGenerateUniqueJTI verifies JTI generation.
func TestGenerateUniqueJTI(t *testing.T) {
	jti := generateUniqueJTI()

	// Should be base64 URL-safe encoded
	if jti == "" {
		t.Fatal("JTI is empty")
	}

	// Verify it contains only valid base64 URL-safe characters
	for _, c := range jti {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			t.Errorf("JTI contains invalid character: %c", c)
		}
	}
}

// TestGenerateUniqueJTIUniqueness verifies JTI uniqueness.
func TestGenerateUniqueJTIUniqueness(t *testing.T) {
	jtis := make(map[string]bool)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		jti := generateUniqueJTI()
		if jtis[jti] {
			t.Errorf("Generated duplicate JTI: %s at iteration %d", jti, i)
		}
		jtis[jti] = true
	}

	if len(jtis) != iterations {
		t.Errorf("Expected %d unique JTIs, got %d", iterations, len(jtis))
	}
}

// TestGenerateRandomString verifies random string generation.
func TestGenerateRandomString(t *testing.T) {
	lengths := []int{8, 16, 32, 64}

	for _, length := range lengths {
		str := generateRandomString(length)

		if len(str) != length {
			t.Errorf("Expected length %d, got %d", length, len(str))
		}

		// Verify it contains only base64 URL-safe characters
		for _, c := range str {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				t.Errorf("String contains invalid character: %c", c)
			}
		}
	}
}

// TestCreateDPoPProof verifies DPoP proof creation.
func TestCreateDPoPProof(t *testing.T) {
	key, _ := GenerateDPoPKey()
	method := "POST"
	uri := "https://pds.example.com/xrpc/com.atproto.repo.createRecord"
	accessToken := "test-access-token"
	nonce := "test-nonce"

	proof, err := createDPoPProof(key, method, uri, accessToken, nonce)
	if err != nil {
		t.Fatalf("createDPoPProof failed: %v", err)
	}

	if proof == "" {
		t.Fatal("Proof is empty")
	}

	// Proof should be a JWT (3 parts separated by dots)
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Errorf("Expected JWT with 3 parts, got %d", len(parts))
	}
}

// TestCreateDPoPProofStructure verifies DPoP proof JWT structure.
func TestCreateDPoPProofStructure(t *testing.T) {
	key, _ := GenerateDPoPKey()
	method := "GET"
	uri := "https://pds.example.com/xrpc/app.bsky.feed.getTimeline"
	accessToken := "test-token"
	nonce := "server-nonce"

	proofString, err := createDPoPProof(key, method, uri, accessToken, nonce)
	if err != nil {
		t.Fatalf("createDPoPProof failed: %v", err)
	}

	// Parse the JWT
	token, err := jwt.Parse(proofString, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("Failed to parse JWT: %v", err)
	}

	// Verify header
	if token.Header["typ"] != "dpop+jwt" {
		t.Errorf("Expected typ 'dpop+jwt', got %v", token.Header["typ"])
	}

	if token.Header["alg"] != "ES256" {
		t.Errorf("Expected alg 'ES256', got %v", token.Header["alg"])
	}

	jwk, ok := token.Header["jwk"].(map[string]interface{})
	if !ok {
		t.Fatal("jwk header missing or wrong type")
	}

	if jwk["kty"] != "EC" {
		t.Errorf("Expected kty 'EC', got %v", jwk["kty"])
	}

	if jwk["crv"] != "P-256" {
		t.Errorf("Expected crv 'P-256', got %v", jwk["crv"])
	}

	// Verify claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Claims are not MapClaims")
	}

	if claims["htm"] != method {
		t.Errorf("Expected htm '%s', got %v", method, claims["htm"])
	}

	expectedHTU := "https://pds.example.com/xrpc/app.bsky.feed.getTimeline"
	if claims["htu"] != expectedHTU {
		t.Errorf("Expected htu '%s', got %v", expectedHTU, claims["htu"])
	}

	if claims["jti"] == nil {
		t.Error("JTI claim missing")
	}

	if claims["iat"] == nil {
		t.Error("IAT claim missing")
	}

	if claims["nonce"] != nonce {
		t.Errorf("Expected nonce '%s', got %v", nonce, claims["nonce"])
	}

	// Verify ath (access token hash)
	if claims["ath"] == nil {
		t.Error("ATH claim missing")
	} else {
		expectedHash := sha256.Sum256([]byte(accessToken))
		expectedATH := base64.RawURLEncoding.EncodeToString(expectedHash[:])
		if claims["ath"] != expectedATH {
			t.Errorf("ATH hash mismatch: expected %s, got %v", expectedATH, claims["ath"])
		}
	}
}

// TestCreateDPoPProofWithoutNonce verifies proof creation without nonce.
func TestCreateDPoPProofWithoutNonce(t *testing.T) {
	key, _ := GenerateDPoPKey()
	method := "POST"
	uri := "https://pds.example.com/api"
	accessToken := "token"
	nonce := "" // No nonce

	proofString, err := createDPoPProof(key, method, uri, accessToken, nonce)
	if err != nil {
		t.Fatalf("createDPoPProof failed: %v", err)
	}

	// Parse JWT
	token, _ := jwt.Parse(proofString, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})

	claims := token.Claims.(jwt.MapClaims)

	// Nonce should not be present
	if _, exists := claims["nonce"]; exists {
		t.Error("Nonce claim should not be present when nonce is empty")
	}
}

// TestCreateDPoPProofWithoutAccessToken verifies proof creation without access token.
func TestCreateDPoPProofWithoutAccessToken(t *testing.T) {
	key, _ := GenerateDPoPKey()
	method := "GET"
	uri := "https://pds.example.com/api"
	accessToken := "" // No access token
	nonce := "nonce"

	proofString, err := createDPoPProof(key, method, uri, accessToken, nonce)
	if err != nil {
		t.Fatalf("createDPoPProof failed: %v", err)
	}

	// Parse JWT
	token, _ := jwt.Parse(proofString, func(token *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})

	claims := token.Claims.(jwt.MapClaims)

	// ATH should not be present
	if _, exists := claims["ath"]; exists {
		t.Error("ATH claim should not be present when accessToken is empty")
	}
}

// TestNewTransport verifies transport initialization.
func TestNewTransport(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"
	nonce := "test-nonce"

	transport := NewTransport(nil, key, token, nonce)

	if transport == nil {
		t.Fatal("Transport is nil")
	}

	dpopT, ok := transport.(*Transport)
	if !ok {
		t.Fatal("Transport is not *Transport")
	}

	if dpopT.dpopKey != key {
		t.Error("DPoP key not set correctly")
	}

	if dpopT.token != token {
		t.Errorf("Token: expected %s, got %s", token, dpopT.token)
	}

	if dpopT.nonce != nonce {
		t.Errorf("Nonce: expected %s, got %s", nonce, dpopT.nonce)
	}

	if dpopT.underlying == nil {
		t.Error("Underlying transport should default to http.DefaultTransport")
	}
}

// TestTransportGetNonce verifies GetNonce method.
func TestTransportGetNonce(t *testing.T) {
	key, _ := GenerateDPoPKey()
	initialNonce := "initial-nonce"

	transport := NewTransport(nil, key, "token", initialNonce)
	dpopT := transport.(*Transport)

	retrievedNonce := dpopT.GetNonce()
	if retrievedNonce != initialNonce {
		t.Errorf("Expected nonce %s, got %s", initialNonce, retrievedNonce)
	}

	// Update nonce
	dpopT.mu.Lock()
	dpopT.nonce = "updated-nonce"
	dpopT.mu.Unlock()

	retrievedNonce = dpopT.GetNonce()
	if retrievedNonce != "updated-nonce" {
		t.Errorf("Expected updated nonce 'updated-nonce', got %s", retrievedNonce)
	}
}

// TestTransportRoundTrip verifies basic request with DPoP headers.
func TestTransportRoundTrip(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"

	// Create a test server that verifies DPoP headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify DPoP header is present
		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			t.Error("DPoP header missing")
		}

		// Verify Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "DPoP "+token {
			t.Errorf("Authorization header: expected 'DPoP %s', got '%s'", token, authHeader)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	transport := NewTransport(nil, key, token, "")
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

// TestTransportNonceRetry verifies nonce retry mechanism.
func TestTransportNonceRetry(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"
	newNonce := "server-provided-nonce"

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount == 1 {
			// First request: return 401 with nonce requirement
			w.Header().Set("DPoP-Nonce", newNonce)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		} else {
			// Second request: verify nonce is present and succeed
			dpopHeader := r.Header.Get("DPoP")
			token, _ := jwt.Parse(dpopHeader, func(token *jwt.Token) (interface{}, error) {
				return &key.PublicKey, nil
			})

			claims := token.Claims.(jwt.MapClaims)
			if claims["nonce"] != newNonce {
				t.Errorf("Expected nonce '%s' in retry, got %v", newNonce, claims["nonce"])
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}
	}))
	defer server.Close()

	transport := NewTransport(nil, key, token, "")
	dpopT := transport.(*Transport)
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 after retry, got %d", resp.StatusCode)
	}

	if requestCount != 2 {
		t.Errorf("Expected 2 requests (initial + retry), got %d", requestCount)
	}

	// Verify nonce was updated in transport
	if dpopT.GetNonce() != newNonce {
		t.Errorf("Nonce not updated: expected %s, got %s", newNonce, dpopT.GetNonce())
	}
}

// TestTransportNonceUpdate verifies nonce is updated from successful responses.
func TestTransportNonceUpdate(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"
	serverNonce := "server-nonce-123"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return success with a new nonce
		w.Header().Set("DPoP-Nonce", serverNonce)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

	transport := NewTransport(nil, key, token, "")
	dpopT := transport.(*Transport)
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify nonce was updated
	if dpopT.GetNonce() != serverNonce {
		t.Errorf("Nonce not updated: expected %s, got %s", serverNonce, dpopT.GetNonce())
	}
}

// TestTransportNoRetryOnNonNonceError verifies no retry for non-nonce errors.
func TestTransportNoRetryOnNonNonceError(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		// Return 401 without nonce requirement
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token"}`))
	}))
	defer server.Close()

	transport := NewTransport(nil, key, token, "")
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", resp.StatusCode)
	}

	if requestCount != 1 {
		t.Errorf("Expected 1 request (no retry), got %d", requestCount)
	}
}

// TestTransportReplayErrorRetry verifies replay errors trigger nonce retry.
func TestTransportReplayErrorRetry(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"
	newNonce := "fresh-nonce-after-replay"

	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount == 1 {
			// First request: return 401 with replay error
			w.Header().Set("DPoP-Nonce", newNonce)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid_dpop_proof","error_description":"DPoP proof replayed"}`))
		} else {
			// Second request: verify nonce is present and succeed
			dpopHeader := r.Header.Get("DPoP")
			token, _ := jwt.Parse(dpopHeader, func(token *jwt.Token) (interface{}, error) {
				return &key.PublicKey, nil
			})

			claims := token.Claims.(jwt.MapClaims)
			if claims["nonce"] != newNonce {
				t.Errorf("Expected nonce '%s' in retry after replay, got %v", newNonce, claims["nonce"])
			}

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("success"))
		}
	}))
	defer server.Close()

	transport := NewTransport(nil, key, token, "")
	dpopT := transport.(*Transport)
	client := &http.Client{Transport: transport}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 after replay retry, got %d", resp.StatusCode)
	}

	if requestCount != 2 {
		t.Errorf("Expected 2 requests (initial + retry after replay), got %d", requestCount)
	}

	// Verify nonce was updated in transport
	if dpopT.GetNonce() != newNonce {
		t.Errorf("Nonce not updated after replay: expected %s, got %s", newNonce, dpopT.GetNonce())
	}
}

// TestDPoPProofHTUConstruction verifies HTU is constructed correctly.
func TestDPoPProofHTUConstruction(t *testing.T) {
	key, _ := GenerateDPoPKey()

	testCases := []struct {
		uri         string
		expectedHTU string
	}{
		{
			uri:         "https://pds.example.com/xrpc/com.atproto.repo.createRecord",
			expectedHTU: "https://pds.example.com/xrpc/com.atproto.repo.createRecord",
		},
		{
			uri:         "https://pds.example.com:443/api?param=value",
			expectedHTU: "https://pds.example.com:443/api",
		},
		{
			uri:         "http://localhost:8080/callback?code=abc&state=xyz",
			expectedHTU: "http://localhost:8080/callback",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.uri, func(t *testing.T) {
			proofString, _ := createDPoPProof(key, "POST", tc.uri, "token", "")

			token, _ := jwt.Parse(proofString, func(token *jwt.Token) (interface{}, error) {
				return &key.PublicKey, nil
			})

			claims := token.Claims.(jwt.MapClaims)
			if claims["htu"] != tc.expectedHTU {
				t.Errorf("Expected htu '%s', got %v", tc.expectedHTU, claims["htu"])
			}
		})
	}
}

// TestTransportWithCustomUnderlying verifies custom underlying transport is used.
func TestTransportWithCustomUnderlying(t *testing.T) {
	key, _ := GenerateDPoPKey()
	customTransportUsed := false

	customTransport := &customRoundTripper{
		callback: func() {
			customTransportUsed = true
		},
	}

	transport := NewTransport(customTransport, key, "token", "")
	client := &http.Client{Transport: transport}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client.Get(server.URL)

	if !customTransportUsed {
		t.Error("Custom underlying transport was not used")
	}
}

// customRoundTripper for testing
type customRoundTripper struct {
	callback func()
}

func (c *customRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	c.callback()
	return http.DefaultTransport.RoundTrip(req)
}

// TestDPoPProofJWKPublicKey verifies JWK contains correct public key.
func TestDPoPProofJWKPublicKey(t *testing.T) {
	key, _ := GenerateDPoPKey()

	proofString, _ := createDPoPProof(key, "GET", "https://example.com/api", "", "")

	// Parse just the header
	parts := strings.Split(proofString, ".")
	headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])

	var header map[string]interface{}
	json.Unmarshal(headerBytes, &header)

	jwk := header["jwk"].(map[string]interface{})

	// Decode x and y coordinates
	xBytes, _ := base64.RawURLEncoding.DecodeString(jwk["x"].(string))
	yBytes, _ := base64.RawURLEncoding.DecodeString(jwk["y"].(string))

	// Compare with actual public key
	if string(xBytes) != string(key.PublicKey.X.Bytes()) {
		t.Error("JWK x coordinate doesn't match public key")
	}

	if string(yBytes) != string(key.PublicKey.Y.Bytes()) {
		t.Error("JWK y coordinate doesn't match public key")
	}
}

// TestTransportConcurrentRequests verifies thread safety.
func TestTransportConcurrentRequests(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	transport := NewTransport(nil, key, token, "")
	client := &http.Client{Transport: transport}

	// Launch multiple concurrent requests
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			req, _ := http.NewRequestWithContext(context.Background(), "GET", server.URL, nil)
			resp, err := client.Do(req)
			if err != nil {
				t.Errorf("Concurrent request failed: %v", err)
			}
			if resp != nil {
				resp.Body.Close()
			}
			done <- true
		}()
	}

	// Wait for all requests
	for i := 0; i < 10; i++ {
		<-done
	}

	t.Log("Concurrent requests completed successfully")
}
