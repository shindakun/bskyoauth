package testutil

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestMockOAuthServer verifies the mock OAuth server works.
func TestMockOAuthServer(t *testing.T) {
	server := NewMockOAuthServer(t)
	defer server.Close()

	// Test metadata endpoint
	resp, err := http.Get(server.BaseURL + "/.well-known/oauth-authorization-server")
	AssertNoError(t, err, "Metadata request should succeed")
	defer resp.Body.Close()

	AssertEqual(t, resp.StatusCode, http.StatusOK, "Metadata should return 200")

	var metadata map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&metadata)
	AssertNoError(t, err, "Metadata JSON should decode")

	AssertEqual(t, metadata["issuer"], server.BaseURL, "Issuer should match server URL")
	AssertNotNil(t, metadata["authorization_endpoint"], "Should have authorization endpoint")
	AssertNotNil(t, metadata["token_endpoint"], "Should have token endpoint")
}

// TestMockOAuthServerJWKS verifies JWKS endpoint works.
func TestMockOAuthServerJWKS(t *testing.T) {
	server := NewMockOAuthServer(t)
	defer server.Close()

	resp, err := http.Get(server.BaseURL + "/.well-known/jwks.json")
	AssertNoError(t, err, "JWKS request should succeed")
	defer resp.Body.Close()

	AssertEqual(t, resp.StatusCode, http.StatusOK, "JWKS should return 200")

	var jwks map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	AssertNoError(t, err, "JWKS JSON should decode")

	keys, ok := jwks["keys"].([]interface{})
	AssertTrue(t, ok, "Should have keys array")
	AssertTrue(t, len(keys) > 0, "Should have at least one key")
}

// TestMockPDSServer verifies the mock PDS server works.
func TestMockPDSServer(t *testing.T) {
	server := NewMockPDSServer(t)
	defer server.Close()

	// Test describe server endpoint
	resp, err := http.Get(server.BaseURL + "/xrpc/com.atproto.server.describeServer")
	AssertNoError(t, err, "Describe server request should succeed")
	defer resp.Body.Close()

	AssertEqual(t, resp.StatusCode, http.StatusOK, "Describe server should return 200")

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	AssertNoError(t, err, "Response JSON should decode")

	AssertNotNil(t, data["did"], "Should have DID")
}

// TestMockHandleServer verifies the mock handle server works.
func TestMockHandleServer(t *testing.T) {
	server := NewMockHandleServer(t)
	defer server.Close()

	// Test existing handle
	resp, err := http.Get(server.BaseURL + "/xrpc/com.atproto.identity.resolveHandle?handle=test.bsky.social")
	AssertNoError(t, err, "Resolve handle request should succeed")
	defer resp.Body.Close()

	AssertEqual(t, resp.StatusCode, http.StatusOK, "Resolve handle should return 200")

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	AssertNoError(t, err, "Response JSON should decode")

	AssertEqual(t, data["did"], "did:plc:test123abc", "Should resolve to correct DID")
}

// TestMockHandleServerAddHandle verifies adding custom handles works.
func TestMockHandleServerAddHandle(t *testing.T) {
	server := NewMockHandleServer(t)
	defer server.Close()

	// Add a custom handle
	server.AddHandle("custom.example.com", "did:plc:custom999")

	// Test custom handle
	resp, err := http.Get(server.BaseURL + "/xrpc/com.atproto.identity.resolveHandle?handle=custom.example.com")
	AssertNoError(t, err, "Resolve custom handle request should succeed")
	defer resp.Body.Close()

	AssertEqual(t, resp.StatusCode, http.StatusOK, "Resolve custom handle should return 200")

	var data map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&data)
	AssertNoError(t, err, "Response JSON should decode")

	AssertEqual(t, data["did"], "did:plc:custom999", "Should resolve to custom DID")
}

// TestMockHandleServerNotFound verifies 404 for unknown handles.
func TestMockHandleServerNotFound(t *testing.T) {
	server := NewMockHandleServer(t)
	defer server.Close()

	resp, err := http.Get(server.BaseURL + "/xrpc/com.atproto.identity.resolveHandle?handle=nonexistent.example.com")
	AssertNoError(t, err, "Request should succeed even for unknown handle")
	defer resp.Body.Close()

	AssertEqual(t, resp.StatusCode, http.StatusNotFound, "Unknown handle should return 404")
}
