package testutil

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

// AssertNoError fails the test if err is not nil.
func AssertNoError(t *testing.T, err error, message string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", message, err)
	}
}

// AssertError fails the test if err is nil.
func AssertError(t *testing.T, err error, message string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected error but got nil", message)
	}
}

// AssertEqual fails the test if got != want.
func AssertEqual(t *testing.T, got, want interface{}, message string) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: got %v, want %v", message, got, want)
	}
}

// AssertNotEqual fails the test if got == want.
func AssertNotEqual(t *testing.T, got, want interface{}, message string) {
	t.Helper()
	if got == want {
		t.Fatalf("%s: got %v, did not want %v", message, got, want)
	}
}

// AssertNil fails the test if value is not nil.
func AssertNil(t *testing.T, value interface{}, message string) {
	t.Helper()
	if value != nil {
		t.Fatalf("%s: expected nil but got %v", message, value)
	}
}

// AssertNotNil fails the test if value is nil.
func AssertNotNil(t *testing.T, value interface{}, message string) {
	t.Helper()
	if value == nil {
		t.Fatalf("%s: expected non-nil value", message)
	}
}

// AssertTrue fails the test if condition is false.
func AssertTrue(t *testing.T, condition bool, message string) {
	t.Helper()
	if !condition {
		t.Fatalf("%s: expected true but got false", message)
	}
}

// AssertFalse fails the test if condition is true.
func AssertFalse(t *testing.T, condition bool, message string) {
	t.Helper()
	if condition {
		t.Fatalf("%s: expected false but got true", message)
	}
}

// AssertContains fails the test if substring is not in str.
func AssertContains(t *testing.T, str, substring, message string) {
	t.Helper()
	if !contains(str, substring) {
		t.Fatalf("%s: expected %q to contain %q", message, str, substring)
	}
}

// AssertNotContains fails the test if substring is in str.
func AssertNotContains(t *testing.T, str, substring, message string) {
	t.Helper()
	if contains(str, substring) {
		t.Fatalf("%s: expected %q not to contain %q", message, str, substring)
	}
}

func contains(str, substring string) bool {
	return len(str) >= len(substring) && (str == substring || len(substring) == 0 || indexOf(str, substring) >= 0)
}

func indexOf(str, substring string) int {
	for i := 0; i <= len(str)-len(substring); i++ {
		if str[i:i+len(substring)] == substring {
			return i
		}
	}
	return -1
}

// AssertPanics fails the test if the function does not panic.
func AssertPanics(t *testing.T, fn func(), message string) {
	t.Helper()
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("%s: expected panic but did not panic", message)
		}
	}()
	fn()
}

// NewTestContext returns a context with a test timeout.
func NewTestContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*1000000000) // 30 seconds
	t.Cleanup(cancel)
	return ctx
}

// MockHTTPClient creates a mock HTTP client that returns predefined responses.
type MockHTTPClient struct {
	Responses []*http.Response
	Errors    []error
	Requests  []*http.Request
	index     int
}

// NewMockHTTPClient creates a new mock HTTP client.
func NewMockHTTPClient() *MockHTTPClient {
	return &MockHTTPClient{
		Responses: []*http.Response{},
		Errors:    []error{},
		Requests:  []*http.Request{},
	}
}

// AddResponse adds a response to the mock client's queue.
func (m *MockHTTPClient) AddResponse(statusCode int, body string) {
	m.Responses = append(m.Responses, &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	})
	m.Errors = append(m.Errors, nil)
}

// AddError adds an error to the mock client's queue.
func (m *MockHTTPClient) AddError(err error) {
	m.Responses = append(m.Responses, nil)
	m.Errors = append(m.Errors, err)
}

// Do implements the http.Client.Do interface.
func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.Requests = append(m.Requests, req)

	if m.index >= len(m.Responses) {
		return nil, io.EOF
	}

	resp := m.Responses[m.index]
	err := m.Errors[m.index]
	m.index++

	return resp, err
}

// Reset resets the mock client state.
func (m *MockHTTPClient) Reset() {
	m.Responses = []*http.Response{}
	m.Errors = []error{}
	m.Requests = []*http.Request{}
	m.index = 0
}

// RequestCount returns the number of requests made.
func (m *MockHTTPClient) RequestCount() int {
	return len(m.Requests)
}

// LastRequest returns the most recent request, or nil if no requests were made.
func (m *MockHTTPClient) LastRequest() *http.Request {
	if len(m.Requests) == 0 {
		return nil
	}
	return m.Requests[len(m.Requests)-1]
}

// MockRoundTripper implements http.RoundTripper for testing.
type MockRoundTripper struct {
	RoundTripFunc func(*http.Request) (*http.Response, error)
}

// RoundTrip implements http.RoundTripper.
func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req)
}

// NewMockRoundTripper creates a new mock round tripper.
func NewMockRoundTripper(fn func(*http.Request) (*http.Response, error)) *MockRoundTripper {
	return &MockRoundTripper{
		RoundTripFunc: fn,
	}
}
