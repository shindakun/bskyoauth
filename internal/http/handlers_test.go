package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockLogger implements the Logger interface for testing
type mockLogger struct{}

func (m *mockLogger) Info(msg string, args ...interface{})  {}
func (m *mockLogger) Warn(msg string, args ...interface{})  {}
func (m *mockLogger) Error(msg string, args ...interface{}) {}

// TestLogin_InvalidHandle tests that invalid handles return 400 not 500
func TestLogin_InvalidHandle(t *testing.T) {
	// Test the specific case that was reported
	invalidHandle := "at:zsdfasd:asdfad"

	handlers := &Handlers{
		LoggerGetter: func(ctx context.Context) Logger {
			return &mockLogger{}
		},
		ValidateHandle: func(handle string) error {
			// Simulate the validation error from syntax.ParseAtIdentifier
			if handle == invalidHandle {
				return errors.New("handle format is invalid: handle syntax didn't validate via regex: " + handle)
			}
			return nil
		},
		AuthFlow: nil, // Should not be called if validation fails
	}

	req := httptest.NewRequest("GET", "/login?handle="+invalidHandle, nil)
	w := httptest.NewRecorder()

	handler := handlers.Login()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (Bad Request), got %d", http.StatusBadRequest, w.Code)
		t.Logf("Response body: %s", w.Body.String())
	}

	if w.Code == http.StatusInternalServerError {
		t.Error("Got 500 Internal Server Error when 400 Bad Request was expected")
		t.Logf("This indicates the validation is not catching the error early enough")
	}
}

// TestLogin_MissingHandle tests that missing handle returns 400
func TestLogin_MissingHandle(t *testing.T) {
	handlers := &Handlers{
		LoggerGetter: func(ctx context.Context) Logger {
			return &mockLogger{}
		},
		ValidateHandle: func(handle string) error {
			return nil
		},
	}

	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()

	handler := handlers.Login()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status %d (Bad Request), got %d", http.StatusBadRequest, w.Code)
	}
}

// TestLogin_ValidHandle tests that valid handles proceed to auth flow
func TestLogin_ValidHandle(t *testing.T) {
	called := false
	mockAuthFlow := &mockAuthFlow{
		startFunc: func(ctx context.Context, handle string) (*FlowState, error) {
			called = true
			return &FlowState{AuthURL: "https://example.com/auth"}, nil
		},
	}

	handlers := &Handlers{
		LoggerGetter: func(ctx context.Context) Logger {
			return &mockLogger{}
		},
		ValidateHandle: func(handle string) error {
			return nil
		},
		AuthFlow: mockAuthFlow,
	}

	req := httptest.NewRequest("GET", "/login?handle=user.bsky.social", nil)
	w := httptest.NewRecorder()

	handler := handlers.Login()
	handler(w, req)

	if !called {
		t.Error("AuthFlow.StartAuthFlow was not called for valid handle")
	}

	if w.Code != http.StatusFound {
		t.Errorf("expected status %d (Found/Redirect), got %d", http.StatusFound, w.Code)
	}
}

// mockAuthFlow implements AuthFlow interface for testing
type mockAuthFlow struct {
	startFunc    func(ctx context.Context, handle string) (*FlowState, error)
	completeFunc func(ctx context.Context, code, state, iss string) (*Session, error)
}

func (m *mockAuthFlow) StartAuthFlow(ctx context.Context, handle string) (*FlowState, error) {
	if m.startFunc != nil {
		return m.startFunc(ctx, handle)
	}
	return nil, errors.New("not implemented")
}

func (m *mockAuthFlow) CompleteAuthFlow(ctx context.Context, code, state, iss string) (*Session, error) {
	if m.completeFunc != nil {
		return m.completeFunc(ctx, code, state, iss)
	}
	return nil, errors.New("not implemented")
}
