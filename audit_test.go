package bskyoauth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNoOpAuditLogger verifies the default no-op logger doesn't cause errors.
func TestNoOpAuditLogger(t *testing.T) {
	logger := &NoOpAuditLogger{}
	ctx := context.Background()

	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: AuditEventAuthStart,
		Action:    "test_action",
		Result:    AuditResultSuccess,
	}

	err := logger.Log(ctx, event)
	if err != nil {
		t.Errorf("NoOpAuditLogger.Log() returned error: %v", err)
	}
}

// TestSetAuditLogger verifies setting and getting the global audit logger.
func TestSetAuditLogger(t *testing.T) {
	// Save original logger
	originalLogger := GetAuditLogger()
	defer SetAuditLogger(originalLogger)

	// Test setting a custom logger
	customLogger := &NoOpAuditLogger{}
	SetAuditLogger(customLogger)

	retrieved := GetAuditLogger()
	if retrieved != customLogger {
		t.Error("GetAuditLogger() did not return the set logger")
	}

	// Test setting nil (should revert to no-op)
	SetAuditLogger(nil)
	retrieved = GetAuditLogger()
	if _, ok := retrieved.(*NoOpAuditLogger); !ok {
		t.Error("Setting nil should revert to NoOpAuditLogger")
	}
}

// TestLogAuditEvent verifies the convenience function enriches events.
func TestLogAuditEvent(t *testing.T) {
	// Save original logger
	originalLogger := GetAuditLogger()
	defer SetAuditLogger(originalLogger)

	// Create mock logger
	var capturedEvent AuditEvent
	mockLogger := &mockAuditLogger{
		logFunc: func(ctx context.Context, event AuditEvent) error {
			capturedEvent = event
			return nil
		},
	}
	SetAuditLogger(mockLogger)

	// Create context with request ID and session ID
	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyRequestID, "test-request-123")
	ctx = context.WithValue(ctx, ContextKeySessionID, "test-session-456")

	// Log event without timestamp
	event := AuditEvent{
		EventType: AuditEventPostCreate,
		Actor:     "did:plc:test123",
		Action:    "create_post",
		Result:    AuditResultSuccess,
	}

	err := LogAuditEvent(ctx, event)
	if err != nil {
		t.Fatalf("LogAuditEvent() returned error: %v", err)
	}

	// Verify enrichment
	if capturedEvent.Timestamp.IsZero() {
		t.Error("LogAuditEvent should set Timestamp if not provided")
	}
	if capturedEvent.RequestID != "test-request-123" {
		t.Errorf("Expected RequestID 'test-request-123', got '%s'", capturedEvent.RequestID)
	}
	if capturedEvent.SessionID != "test-session-456" {
		t.Errorf("Expected SessionID 'test-session-456', got '%s'", capturedEvent.SessionID)
	}
	if capturedEvent.EventType != AuditEventPostCreate {
		t.Errorf("Event type should be preserved")
	}
}

// TestFileAuditLogger tests basic file logging functionality.
func TestFileAuditLogger(t *testing.T) {
	// Create temp directory
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	// Create logger
	logger, err := NewFileAuditLogger(logFile)
	if err != nil {
		t.Fatalf("NewFileAuditLogger() failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Log some events
	events := []AuditEvent{
		{
			Timestamp: time.Now().UTC(),
			EventType: AuditEventAuthStart,
			Action:    "start_oauth_flow",
			Resource:  "user.bsky.social",
			Result:    AuditResultSuccess,
		},
		{
			Timestamp: time.Now().UTC(),
			EventType: AuditEventAuthSuccess,
			Actor:     "did:plc:test123",
			Action:    "complete_oauth_flow",
			Result:    AuditResultSuccess,
		},
		{
			Timestamp: time.Now().UTC(),
			EventType: AuditEventPostCreate,
			Actor:     "did:plc:test123",
			Action:    "create_post",
			Resource:  "at://did:plc:test123/app.bsky.feed.post/abc123",
			Result:    AuditResultSuccess,
		},
	}

	for _, event := range events {
		if err := logger.Log(ctx, event); err != nil {
			t.Errorf("Log() failed: %v", err)
		}
	}

	// Close to flush
	if err := logger.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Read and verify log file
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(events) {
		t.Errorf("Expected %d log lines, got %d", len(events), len(lines))
	}

	// Verify each line is valid JSON and contains expected data
	for i, line := range lines {
		var loggedEvent AuditEvent
		if err := json.Unmarshal([]byte(line), &loggedEvent); err != nil {
			t.Errorf("Line %d is not valid JSON: %v", i+1, err)
			continue
		}

		if loggedEvent.EventType != events[i].EventType {
			t.Errorf("Event %d: expected type %s, got %s", i, events[i].EventType, loggedEvent.EventType)
		}
		if loggedEvent.Action != events[i].Action {
			t.Errorf("Event %d: expected action %s, got %s", i, events[i].Action, loggedEvent.Action)
		}
	}
}

// TestFileAuditLoggerConcurrent tests thread-safety of FileAuditLogger.
func TestFileAuditLoggerConcurrent(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "audit.log")

	logger, err := NewFileAuditLogger(logFile)
	if err != nil {
		t.Fatalf("NewFileAuditLogger() failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := AuditEvent{
					Timestamp: time.Now().UTC(),
					EventType: AuditEventPostCreate,
					Actor:     "did:plc:test",
					Action:    "concurrent_test",
					Metadata: map[string]interface{}{
						"goroutine": id,
						"event":     j,
					},
					Result: AuditResultSuccess,
				}
				if err := logger.Log(ctx, event); err != nil {
					t.Errorf("Log() failed: %v", err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Close to flush
	if err := logger.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Verify we got all events
	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	expectedLines := numGoroutines * eventsPerGoroutine
	if len(lines) != expectedLines {
		t.Errorf("Expected %d log lines, got %d", expectedLines, len(lines))
	}

	// Verify all lines are valid JSON
	for i, line := range lines {
		var event AuditEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Errorf("Line %d is not valid JSON: %v", i+1, err)
		}
	}
}

// TestFileAuditLoggerDirectoryCreation verifies directory creation.
func TestFileAuditLoggerDirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "nested", "dir", "audit.log")

	logger, err := NewFileAuditLogger(logFile)
	if err != nil {
		t.Fatalf("NewFileAuditLogger() failed: %v", err)
	}
	defer logger.Close()

	// Verify directory was created
	dir := filepath.Dir(logFile)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("Directory should have been created")
	}

	// Verify file was created
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		t.Error("Log file should have been created")
	}
}

// TestRotatingFileAuditLogger tests daily log rotation.
func TestRotatingFileAuditLogger(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewRotatingFileAuditLogger(tmpDir)
	if err != nil {
		t.Fatalf("NewRotatingFileAuditLogger() failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Log an event
	event := AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: AuditEventAuthStart,
		Action:    "test_action",
		Result:    AuditResultSuccess,
	}

	if err := logger.Log(ctx, event); err != nil {
		t.Errorf("Log() failed: %v", err)
	}

	// Verify file was created with today's date
	expectedDate := time.Now().UTC().Format("2006-01-02")
	expectedFile := filepath.Join(tmpDir, "audit-"+expectedDate+".log")

	if _, err := os.Stat(expectedFile); os.IsNotExist(err) {
		t.Errorf("Expected log file %s does not exist", expectedFile)
	}

	// Read and verify content
	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	var loggedEvent AuditEvent
	if err := json.Unmarshal(data, &loggedEvent); err != nil {
		t.Errorf("Log file does not contain valid JSON: %v", err)
	}

	if loggedEvent.EventType != AuditEventAuthStart {
		t.Errorf("Expected event type %s, got %s", AuditEventAuthStart, loggedEvent.EventType)
	}
}

// TestRotatingFileAuditLoggerRotation verifies rotation behavior.
func TestRotatingFileAuditLoggerRotation(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewRotatingFileAuditLogger(tmpDir)
	if err != nil {
		t.Fatalf("NewRotatingFileAuditLogger() failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()

	// Get initial file name
	initialDate := time.Now().UTC().Format("2006-01-02")
	initialFile := filepath.Join(tmpDir, "audit-"+initialDate+".log")

	// Log event with current date
	event1 := AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: AuditEventAuthStart,
		Action:    "before_rotation",
		Result:    AuditResultSuccess,
	}
	if err := logger.Log(ctx, event1); err != nil {
		t.Errorf("Log() failed: %v", err)
	}

	// Manually change the current date to trigger rotation on next log
	logger.mu.Lock()
	logger.currentDate = "2023-01-01" // Old date to force rotation
	logger.mu.Unlock()

	// Log event (should trigger rotation to current date)
	event2 := AuditEvent{
		Timestamp: time.Now().UTC(),
		EventType: AuditEventAuthSuccess,
		Action:    "after_rotation",
		Result:    AuditResultSuccess,
	}
	if err := logger.Log(ctx, event2); err != nil {
		t.Errorf("Log() after rotation failed: %v", err)
	}

	// Close to ensure all writes are flushed
	if err := logger.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Verify initial file still exists with first event
	data, err := os.ReadFile(initialFile)
	if err != nil {
		t.Fatalf("Failed to read initial file %s: %v", initialFile, err)
	}

	if !strings.Contains(string(data), "before_rotation") {
		t.Error("Initial file should contain first event")
	}
	if !strings.Contains(string(data), "after_rotation") {
		t.Error("Initial file should contain second event after rotation back to same date")
	}
}

// TestRotatingFileAuditLoggerConcurrent tests thread-safety during rotation.
func TestRotatingFileAuditLoggerConcurrent(t *testing.T) {
	tmpDir := t.TempDir()

	logger, err := NewRotatingFileAuditLogger(tmpDir)
	if err != nil {
		t.Fatalf("NewRotatingFileAuditLogger() failed: %v", err)
	}
	defer logger.Close()

	ctx := context.Background()
	const numGoroutines = 10
	const eventsPerGoroutine = 10

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < eventsPerGoroutine; j++ {
				event := AuditEvent{
					Timestamp: time.Now().UTC(),
					EventType: AuditEventPostCreate,
					Actor:     "did:plc:test",
					Action:    "concurrent_rotation_test",
					Metadata: map[string]interface{}{
						"goroutine": id,
						"event":     j,
					},
					Result: AuditResultSuccess,
				}
				if err := logger.Log(ctx, event); err != nil {
					t.Errorf("Log() failed: %v", err)
				}
			}
		}(i)
	}

	wg.Wait()

	// Close to flush
	if err := logger.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}

	// Verify log file exists and has all events
	expectedDate := time.Now().UTC().Format("2006-01-02")
	expectedFile := filepath.Join(tmpDir, "audit-"+expectedDate+".log")

	data, err := os.ReadFile(expectedFile)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	expectedLines := numGoroutines * eventsPerGoroutine
	if len(lines) != expectedLines {
		t.Errorf("Expected %d log lines, got %d", expectedLines, len(lines))
	}
}

// TestAuditEventStructure verifies AuditEvent fields are properly serialized.
func TestAuditEventStructure(t *testing.T) {
	event := AuditEvent{
		Timestamp: time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC),
		EventType: AuditEventPostCreate,
		Actor:     "did:plc:test123",
		Action:    "create_post",
		Resource:  "at://did:plc:test123/app.bsky.feed.post/abc123",
		Result:    AuditResultSuccess,
		Error:     "",
		Metadata: map[string]interface{}{
			"ip_address": "192.168.1.1",
			"user_agent": "MyApp/1.0",
		},
		RequestID: "req-123",
		SessionID: "sess-456",
	}

	// Marshal to JSON
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	// Unmarshal and verify
	var decoded AuditEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	if decoded.EventType != event.EventType {
		t.Errorf("EventType mismatch: expected %s, got %s", event.EventType, decoded.EventType)
	}
	if decoded.Actor != event.Actor {
		t.Errorf("Actor mismatch: expected %s, got %s", event.Actor, decoded.Actor)
	}
	if decoded.Action != event.Action {
		t.Errorf("Action mismatch: expected %s, got %s", event.Action, decoded.Action)
	}
	if decoded.Resource != event.Resource {
		t.Errorf("Resource mismatch: expected %s, got %s", event.Resource, decoded.Resource)
	}
	if decoded.Result != event.Result {
		t.Errorf("Result mismatch: expected %s, got %s", event.Result, decoded.Result)
	}
	if decoded.RequestID != event.RequestID {
		t.Errorf("RequestID mismatch: expected %s, got %s", event.RequestID, decoded.RequestID)
	}
	if decoded.SessionID != event.SessionID {
		t.Errorf("SessionID mismatch: expected %s, got %s", event.SessionID, decoded.SessionID)
	}

	// Verify metadata
	if decoded.Metadata["ip_address"] != "192.168.1.1" {
		t.Error("Metadata ip_address mismatch")
	}
	if decoded.Metadata["user_agent"] != "MyApp/1.0" {
		t.Error("Metadata user_agent mismatch")
	}
}

// mockAuditLogger is a test helper for capturing logged events.
type mockAuditLogger struct {
	logFunc func(ctx context.Context, event AuditEvent) error
}

func (m *mockAuditLogger) Log(ctx context.Context, event AuditEvent) error {
	if m.logFunc != nil {
		return m.logFunc(ctx, event)
	}
	return nil
}
