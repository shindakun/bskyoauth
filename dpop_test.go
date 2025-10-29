package bskyoauth

import (
	"crypto/elliptic"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGenerateDPoPKey verifies the public DPoP key generation wrapper.
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

// TestNewDPoPTransport verifies the public transport wrapper.
func TestNewDPoPTransport(t *testing.T) {
	key, _ := GenerateDPoPKey()
	token := "test-token"
	nonce := "test-nonce"

	transport := NewDPoPTransport(nil, key, token, nonce)

	if transport == nil {
		t.Fatal("Transport is nil")
	}

	// Verify it works with an HTTP client
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify DPoP header is present
		dpopHeader := r.Header.Get("DPoP")
		if dpopHeader == "" {
			t.Error("DPoP header missing")
		}

		// Verify Authorization header
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "DPoP " + token
		if authHeader != expectedAuth {
			t.Errorf("Authorization header: expected '%s', got '%s'", expectedAuth, authHeader)
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	}))
	defer server.Close()

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
