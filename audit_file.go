package bskyoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileAuditLogger writes audit events to a JSON file.
// Thread-safe for concurrent logging.
//
// Example:
//
//	logger, err := bskyoauth.NewFileAuditLogger("/var/log/myapp/audit.log")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer logger.Close()
//	bskyoauth.SetAuditLogger(logger)
type FileAuditLogger struct {
	file *os.File
	mu   sync.Mutex
	enc  *json.Encoder
}

// NewFileAuditLogger creates a file-based audit logger.
// The file is opened in append mode with restricted permissions (0600).
// Parent directories are created if they don't exist.
func NewFileAuditLogger(path string) (*FileAuditLogger, error) {
	// Create parent directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	// Open file in append mode with restrictive permissions
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file: %w", err)
	}

	return &FileAuditLogger{
		file: file,
		enc:  json.NewEncoder(file),
	}, nil
}

// Log writes an audit event to the file as a JSON line.
// Thread-safe for concurrent calls.
func (f *FileAuditLogger) Log(ctx context.Context, event AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := f.enc.Encode(event); err != nil {
		return fmt.Errorf("failed to encode audit event: %w", err)
	}

	return nil
}

// Close closes the underlying file.
// Should be called when the logger is no longer needed.
func (f *FileAuditLogger) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.file != nil {
		return f.file.Close()
	}
	return nil
}

// RotatingFileAuditLogger writes audit events to daily rotated files.
// Files are named: audit-YYYY-MM-DD.log
// Rotation happens automatically at midnight UTC.
// Thread-safe for concurrent logging.
//
// Example:
//
//	logger, err := bskyoauth.NewRotatingFileAuditLogger("/var/log/myapp")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer logger.Close()
//	bskyoauth.SetAuditLogger(logger)
type RotatingFileAuditLogger struct {
	baseDir     string
	currentFile *os.File
	currentDate string
	mu          sync.Mutex
	enc         *json.Encoder
}

// NewRotatingFileAuditLogger creates a rotating file audit logger.
// Files are created in baseDir with format: audit-YYYY-MM-DD.log
// Rotation happens automatically at midnight UTC.
func NewRotatingFileAuditLogger(baseDir string) (*RotatingFileAuditLogger, error) {
	// Create base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}

	logger := &RotatingFileAuditLogger{
		baseDir: baseDir,
	}

	// Open initial log file
	if err := logger.rotate(); err != nil {
		return nil, err
	}

	return logger, nil
}

// Log writes an audit event to the current log file.
// Automatically rotates to a new file at midnight UTC.
// Thread-safe for concurrent calls.
func (r *RotatingFileAuditLogger) Log(ctx context.Context, event AuditEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if we need to rotate
	currentDate := time.Now().UTC().Format("2006-01-02")
	if currentDate != r.currentDate {
		if err := r.rotateUnlocked(); err != nil {
			return fmt.Errorf("failed to rotate audit log: %w", err)
		}
	}

	// Write event
	if err := r.enc.Encode(event); err != nil {
		return fmt.Errorf("failed to encode audit event: %w", err)
	}

	return nil
}

// Close closes the current log file.
// Should be called when the logger is no longer needed.
func (r *RotatingFileAuditLogger) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.currentFile != nil {
		return r.currentFile.Close()
	}
	return nil
}

// rotate opens a new log file for the current date.
// Must be called with mutex held.
func (r *RotatingFileAuditLogger) rotateUnlocked() error {
	// Close existing file if open
	if r.currentFile != nil {
		if err := r.currentFile.Close(); err != nil {
			return fmt.Errorf("failed to close previous audit log: %w", err)
		}
	}

	// Generate new filename
	currentDate := time.Now().UTC().Format("2006-01-02")
	filename := filepath.Join(r.baseDir, fmt.Sprintf("audit-%s.log", currentDate))

	// Open new file
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open audit log file: %w", err)
	}

	r.currentFile = file
	r.currentDate = currentDate
	r.enc = json.NewEncoder(file)

	return nil
}

// rotate is the public version that acquires the lock
func (r *RotatingFileAuditLogger) rotate() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rotateUnlocked()
}
