package dpop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestTransportBodyRetry tests that request body is properly preserved for retries
func TestTransportBodyRetry(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	requestCount := 0
	var firstBody, secondBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		body, _ := io.ReadAll(r.Body)

		if requestCount == 1 {
			firstBody = body
			// First request - require nonce
			w.Header().Set("DPoP-Nonce", "test-nonce-123")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"use_dpop_nonce"}`))
		} else {
			secondBody = body
			// Second request - success
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"success":true}`))
		}
	}))
	defer server.Close()

	transport := NewTransport(http.DefaultTransport, key, "test-token", "")

	// Create request with body
	testBody := []byte(`{"test":"data","value":123}`)
	req, err := http.NewRequest("POST", server.URL, bytes.NewReader(testBody))
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute request
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if requestCount != 2 {
		t.Errorf("Expected 2 requests (initial + retry), got %d", requestCount)
	}

	// Check that both requests received the same body
	if !bytes.Equal(firstBody, testBody) {
		t.Errorf("First request body mismatch.\nExpected: %s\nGot: %s", testBody, firstBody)
	}

	if !bytes.Equal(secondBody, testBody) {
		t.Errorf("Second request body mismatch.\nExpected: %s\nGot: %s", testBody, secondBody)
	}

	if !bytes.Equal(firstBody, secondBody) {
		t.Errorf("Request bodies differ between attempts.\nFirst: %s\nSecond: %s", firstBody, secondBody)
	}
}
