package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// MockOAuthServer provides a mock OAuth authorization server for testing.
type MockOAuthServer struct {
	Server   *httptest.Server
	BaseURL  string
	t        *testing.T
	handlers map[string]http.HandlerFunc
}

// NewMockOAuthServer creates a new mock OAuth server.
func NewMockOAuthServer(t *testing.T) *MockOAuthServer {
	t.Helper()

	mock := &MockOAuthServer{
		t:        t,
		handlers: make(map[string]http.HandlerFunc),
	}

	// Set up default handlers
	mock.handlers["/.well-known/oauth-authorization-server"] = mock.handleMetadata
	mock.handlers["/.well-known/jwks.json"] = mock.handleJWKS
	mock.handlers["/authorize"] = mock.handleAuthorize
	mock.handlers["/token"] = mock.handleToken
	mock.handlers["/par"] = mock.handlePAR

	// Create the server
	mux := http.NewServeMux()
	for path, handler := range mock.handlers {
		mux.HandleFunc(path, handler)
	}

	mock.Server = httptest.NewServer(mux)
	mock.BaseURL = mock.Server.URL

	return mock
}

// Close closes the mock server.
func (m *MockOAuthServer) Close() {
	m.Server.Close()
}

// SetHandler allows overriding a specific handler for testing.
func (m *MockOAuthServer) SetHandler(path string, handler http.HandlerFunc) {
	m.handlers[path] = handler
}

// handleMetadata returns OAuth server metadata.
func (m *MockOAuthServer) handleMetadata(w http.ResponseWriter, r *http.Request) {
	metadata := map[string]interface{}{
		"issuer":                                m.BaseURL,
		"authorization_endpoint":                m.BaseURL + "/authorize",
		"token_endpoint":                        m.BaseURL + "/token",
		"jwks_uri":                              m.BaseURL + "/.well-known/jwks.json",
		"pushed_authorization_request_endpoint": m.BaseURL + "/par",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"dpop_signing_alg_values_supported":     []string{"ES256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// handleJWKS returns a mock JWKS with a test RSA key.
func (m *MockOAuthServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	// Generate a test RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(w, "Failed to generate key", http.StatusInternalServerError)
		return
	}

	// Convert to JWK format
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "test-key-1",
				"use": "sig",
				"alg": "RS256",
				"n":   n,
				"e":   e,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// handleAuthorize handles the authorization endpoint.
func (m *MockOAuthServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Extract parameters
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")

	if clientID == "" || redirectURI == "" || state == "" {
		http.Error(w, "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Generate a test authorization code
	code := "test-auth-code-" + RandomString(16)

	// Redirect back with code
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s&iss=%s", redirectURI, code, state, m.BaseURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleToken handles the token endpoint.
func (m *MockOAuthServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	grantType := r.FormValue("grant_type")

	var response map[string]interface{}

	switch grantType {
	case "authorization_code":
		response = map[string]interface{}{
			"access_token":  "test-access-token-" + RandomString(16),
			"refresh_token": "test-refresh-token-" + RandomString(16),
			"token_type":    "DPoP",
			"expires_in":    43200, // 12 hours
			"sub":           "did:plc:test123abc",
		}

	case "refresh_token":
		response = map[string]interface{}{
			"access_token":  "test-refreshed-access-token-" + RandomString(16),
			"refresh_token": "test-new-refresh-token-" + RandomString(16),
			"token_type":    "DPoP",
			"expires_in":    43200, // 12 hours
		}

	default:
		http.Error(w, "Unsupported grant type", http.StatusBadRequest)
		return
	}

	// Set DPoP nonce header
	w.Header().Set("DPoP-Nonce", "test-nonce-"+RandomString(8))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handlePAR handles the Pushed Authorization Request endpoint.
func (m *MockOAuthServer) handlePAR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate request URI
	requestURI := "urn:ietf:params:oauth:request_uri:test-" + RandomString(16)

	response := map[string]interface{}{
		"request_uri": requestURI,
		"expires_in":  60,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// MockPDSServer provides a mock AT Protocol PDS server for testing.
type MockPDSServer struct {
	Server   *httptest.Server
	BaseURL  string
	t        *testing.T
	handlers map[string]http.HandlerFunc
}

// NewMockPDSServer creates a new mock PDS server.
func NewMockPDSServer(t *testing.T) *MockPDSServer {
	t.Helper()

	mock := &MockPDSServer{
		t:        t,
		handlers: make(map[string]http.HandlerFunc),
	}

	// Set up default handlers
	mock.handlers["/xrpc/com.atproto.repo.createRecord"] = mock.handleCreateRecord
	mock.handlers["/xrpc/com.atproto.repo.deleteRecord"] = mock.handleDeleteRecord
	mock.handlers["/xrpc/com.atproto.server.describeServer"] = mock.handleDescribeServer

	// Create the server
	mux := http.NewServeMux()
	for path, handler := range mock.handlers {
		mux.HandleFunc(path, handler)
	}

	mock.Server = httptest.NewServer(mux)
	mock.BaseURL = mock.Server.URL

	return mock
}

// Close closes the mock server.
func (m *MockPDSServer) Close() {
	m.Server.Close()
}

// SetHandler allows overriding a specific handler for testing.
func (m *MockPDSServer) SetHandler(path string, handler http.HandlerFunc) {
	m.handlers[path] = handler
}

// handleCreateRecord handles record creation.
func (m *MockPDSServer) handleCreateRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check DPoP header
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		http.Error(w, "Missing DPoP header", http.StatusUnauthorized)
		return
	}

	// Parse request
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Generate response
	rkey := "test-rkey-" + RandomString(13)
	uri := fmt.Sprintf("at://%s/%s/%s", "did:plc:test123abc", req["collection"], rkey)
	cid := "bafyrei" + RandomString(52)

	response := map[string]interface{}{
		"uri": uri,
		"cid": cid,
	}

	// Return fresh DPoP nonce
	w.Header().Set("DPoP-Nonce", "test-nonce-"+RandomString(8))
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleDeleteRecord handles record deletion.
func (m *MockPDSServer) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check DPoP header
	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		http.Error(w, "Missing DPoP header", http.StatusUnauthorized)
		return
	}

	// Return success with fresh DPoP nonce
	w.Header().Set("DPoP-Nonce", "test-nonce-"+RandomString(8))
	w.WriteHeader(http.StatusOK)
}

// handleDescribeServer handles server description.
func (m *MockPDSServer) handleDescribeServer(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"did": "did:plc:testpds123",
		"availableUserDomains": []string{
			"test.example.com",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// MockHandleServer provides a mock handle resolution server.
type MockHandleServer struct {
	Server  *httptest.Server
	BaseURL string
	t       *testing.T
	handles map[string]string // handle -> DID mapping
}

// NewMockHandleServer creates a new mock handle resolution server.
func NewMockHandleServer(t *testing.T) *MockHandleServer {
	t.Helper()

	mock := &MockHandleServer{
		t:       t,
		handles: make(map[string]string),
	}

	// Default handle mappings
	mock.handles["test.bsky.social"] = "did:plc:test123abc"
	mock.handles["alice.bsky.social"] = "did:plc:alice123"
	mock.handles["bob.bsky.social"] = "did:plc:bob456"

	mux := http.NewServeMux()
	mux.HandleFunc("/xrpc/com.atproto.identity.resolveHandle", mock.handleResolveHandle)

	mock.Server = httptest.NewServer(mux)
	mock.BaseURL = mock.Server.URL

	return mock
}

// Close closes the mock server.
func (m *MockHandleServer) Close() {
	m.Server.Close()
}

// AddHandle adds a handle -> DID mapping.
func (m *MockHandleServer) AddHandle(handle, did string) {
	m.handles[handle] = did
}

// handleResolveHandle resolves a handle to a DID.
func (m *MockHandleServer) handleResolveHandle(w http.ResponseWriter, r *http.Request) {
	handle := r.URL.Query().Get("handle")
	if handle == "" {
		http.Error(w, "Missing handle parameter", http.StatusBadRequest)
		return
	}

	// Remove any protocol prefix
	handle = strings.TrimPrefix(handle, "http://")
	handle = strings.TrimPrefix(handle, "https://")

	did, exists := m.handles[handle]
	if !exists {
		http.Error(w, "Handle not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"did": did,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// NewTestDPoPProofKey generates a test ECDSA key and returns it with a JWK thumbprint.
func NewTestDPoPProofKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate DPoP key: %v", err)
	}

	// Generate a simple thumbprint for testing
	thumbprint := "test-thumbprint-" + RandomString(16)

	return key, thumbprint
}

// WaitForCondition waits for a condition to be true or times out.
// Useful for testing async behavior.
func WaitForCondition(t *testing.T, timeout time.Duration, check func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("Timeout waiting for condition: %s", message)
}
