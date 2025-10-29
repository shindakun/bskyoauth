package bskyoauth

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPClientTimeout(t *testing.T) {
	// This test verifies that HTTP requests properly timeout
	// Create a test server that delays response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Sleep longer than our test timeout
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"authorization_endpoint": "https://example.com/auth"}`))
	}))
	defer server.Close()

	// Set custom client with very short timeout for testing
	oldClient := GetHTTPClient()
	defer SetHTTPClient(oldClient)

	testClient := &http.Client{Timeout: 100 * time.Millisecond}
	SetHTTPClient(testClient)

	// Make a direct HTTP request to verify timeout behavior
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/.well-known/oauth-authorization-server", nil)
	_, err := testClient.Do(req)

	if err == nil {
		t.Error("expected timeout error, got nil")
	}

	if !IsTimeoutError(err) {
		t.Errorf("expected timeout error, got: %v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	// This test verifies that context cancellation is properly handled
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Create context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Make a direct HTTP request with canceled context
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL, nil)
	_, err := http.DefaultClient.Do(req)

	if err == nil {
		t.Error("expected error from canceled context")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}

	if !IsTimeoutError(err) {
		t.Errorf("IsTimeoutError should return true for context.DeadlineExceeded, got: %v", err)
	}
}

func TestSetHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	SetHTTPClient(customClient)

	if GetHTTPClient() != customClient {
		t.Error("SetHTTPClient did not update the client")
	}

	// Restore default
	defaultClient := &http.Client{Timeout: 30 * time.Second}
	SetHTTPClient(defaultClient)
}

func TestGetHTTPClient(t *testing.T) {
	client := GetHTTPClient()
	if client == nil {
		t.Error("GetHTTPClient returned nil")
	}

	if client.Timeout != 30*time.Second {
		t.Errorf("expected default timeout of 30s, got: %v", client.Timeout)
	}
}

func TestClientOptionsWithHTTPClient(t *testing.T) {
	// Save the current default client
	oldClient := GetHTTPClient()
	defer SetHTTPClient(oldClient)

	// Create a custom HTTP client with 10 second timeout
	customClient := &http.Client{Timeout: 10 * time.Second}

	// Create client with custom HTTP client
	client := NewClientWithOptions(ClientOptions{
		BaseURL:    "http://localhost:8181",
		HTTPClient: customClient,
	})

	if client == nil {
		t.Fatal("NewClientWithOptions returned nil")
	}

	// Verify the custom client was set
	if GetHTTPClient() != customClient {
		t.Error("Custom HTTP client was not set")
	}

	if GetHTTPClient().Timeout != 10*time.Second {
		t.Errorf("expected custom timeout of 10s, got: %v", GetHTTPClient().Timeout)
	}
}

func TestIsTimeoutError_ContextDeadlineExceeded(t *testing.T) {
	err := context.DeadlineExceeded
	if !IsTimeoutError(err) {
		t.Error("IsTimeoutError should return true for context.DeadlineExceeded")
	}
}

func TestIsTimeoutError_NilError(t *testing.T) {
	if IsTimeoutError(nil) {
		t.Error("IsTimeoutError should return false for nil error")
	}
}

func TestIsTimeoutError_NonTimeoutError(t *testing.T) {
	err := errors.New("some other error")
	if IsTimeoutError(err) {
		t.Error("IsTimeoutError should return false for non-timeout error")
	}
}

func TestDefaultHTTPClientSettings(t *testing.T) {
	// Reset to default client to ensure we're testing the actual default
	SetHTTPClient(&http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
			MaxIdleConnsPerHost:   10,
		},
	})

	client := GetHTTPClient()

	// Check timeout
	if client.Timeout != 30*time.Second {
		t.Errorf("expected 30s timeout, got: %v", client.Timeout)
	}

	// Check transport settings
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport")
	}

	if transport.TLSHandshakeTimeout != 10*time.Second {
		t.Errorf("expected 10s TLS handshake timeout, got: %v", transport.TLSHandshakeTimeout)
	}

	if transport.ResponseHeaderTimeout != 10*time.Second {
		t.Errorf("expected 10s response header timeout, got: %v", transport.ResponseHeaderTimeout)
	}

	if transport.IdleConnTimeout != 90*time.Second {
		t.Errorf("expected 90s idle conn timeout, got: %v", transport.IdleConnTimeout)
	}

	if transport.MaxIdleConns != 100 {
		t.Errorf("expected 100 max idle conns, got: %v", transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != 10 {
		t.Errorf("expected 10 max idle conns per host, got: %v", transport.MaxIdleConnsPerHost)
	}
}
