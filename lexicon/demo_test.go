package lexicon

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestDemoRecord_MarshalCBOR(t *testing.T) {
	tests := []struct {
		name    string
		record  *DemoRecord
		wantErr bool
	}{
		{
			name: "valid record",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "Hello, World!",
				CreatedAt:     "2025-10-29T12:34:56Z",
			},
			wantErr: false,
		},
		{
			name: "empty text",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "",
				CreatedAt:     "2025-10-29T12:34:56Z",
			},
			wantErr: false, // CBOR encoding allows empty strings
		},
		{
			name: "long text",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          strings.Repeat("a", 5000),
				CreatedAt:     "2025-10-29T12:34:56Z",
			},
			wantErr: false,
		},
		{
			name: "text too long",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          strings.Repeat("a", 10001),
				CreatedAt:     "2025-10-29T12:34:56Z",
			},
			wantErr: true,
		},
		{
			name:    "nil record",
			record:  nil,
			wantErr: false, // Nil marshals to CBOR null
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := tt.record.MarshalCBOR(&buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalCBOR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && buf.Len() == 0 && tt.record != nil {
				t.Error("MarshalCBOR() produced empty output for non-nil record")
			}
		})
	}
}

func TestDemoRecord_UnmarshalCBOR(t *testing.T) {
	// First, create a valid CBOR-encoded record
	original := &DemoRecord{
		LexiconTypeID: "com.demo.bskyoauth",
		Text:          "Test message",
		CreatedAt:     "2025-10-29T12:34:56Z",
	}

	var buf bytes.Buffer
	if err := original.MarshalCBOR(&buf); err != nil {
		t.Fatalf("Failed to marshal test record: %v", err)
	}

	// Now unmarshal it
	decoded := &DemoRecord{}
	if err := decoded.UnmarshalCBOR(&buf); err != nil {
		t.Fatalf("UnmarshalCBOR() error = %v", err)
	}

	// Verify fields
	if decoded.LexiconTypeID != original.LexiconTypeID {
		t.Errorf("LexiconTypeID = %v, want %v", decoded.LexiconTypeID, original.LexiconTypeID)
	}
	if decoded.Text != original.Text {
		t.Errorf("Text = %v, want %v", decoded.Text, original.Text)
	}
	if decoded.CreatedAt != original.CreatedAt {
		t.Errorf("CreatedAt = %v, want %v", decoded.CreatedAt, original.CreatedAt)
	}
}

func TestDemoRecord_RoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		record *DemoRecord
	}{
		{
			name: "simple record",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "Hello!",
				CreatedAt:     time.Now().Format(time.RFC3339),
			},
		},
		{
			name: "unicode text",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "Hello 世界 🌍",
				CreatedAt:     time.Now().Format(time.RFC3339),
			},
		},
		{
			name: "long text",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          strings.Repeat("Lorem ipsum ", 100),
				CreatedAt:     time.Now().Format(time.RFC3339),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal
			var buf bytes.Buffer
			if err := tt.record.MarshalCBOR(&buf); err != nil {
				t.Fatalf("MarshalCBOR() error = %v", err)
			}

			// Unmarshal
			decoded := &DemoRecord{}
			if err := decoded.UnmarshalCBOR(&buf); err != nil {
				t.Fatalf("UnmarshalCBOR() error = %v", err)
			}

			// Compare
			if decoded.LexiconTypeID != tt.record.LexiconTypeID {
				t.Errorf("LexiconTypeID mismatch: got %v, want %v", decoded.LexiconTypeID, tt.record.LexiconTypeID)
			}
			if decoded.Text != tt.record.Text {
				t.Errorf("Text mismatch: got %v, want %v", decoded.Text, tt.record.Text)
			}
			if decoded.CreatedAt != tt.record.CreatedAt {
				t.Errorf("CreatedAt mismatch: got %v, want %v", decoded.CreatedAt, tt.record.CreatedAt)
			}
		})
	}
}

func TestDemoRecord_Validate(t *testing.T) {
	now := time.Now().Format(time.RFC3339)

	tests := []struct {
		name    string
		record  *DemoRecord
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid record",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "Hello, World!",
				CreatedAt:     now,
			},
			wantErr: false,
		},
		{
			name:    "nil record",
			record:  nil,
			wantErr: true,
			errMsg:  "record cannot be nil",
		},
		{
			name: "empty text",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "",
				CreatedAt:     now,
			},
			wantErr: true,
			errMsg:  "text field is required",
		},
		{
			name: "missing createdAt",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "Hello!",
				CreatedAt:     "",
			},
			wantErr: true,
			errMsg:  "createdAt field is required",
		},
		{
			name: "invalid createdAt format",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          "Hello!",
				CreatedAt:     "not-a-date",
			},
			wantErr: true,
			errMsg:  "createdAt must be valid RFC3339 timestamp",
		},
		{
			name: "wrong lexicon type",
			record: &DemoRecord{
				LexiconTypeID: "com.example.wrong",
				Text:          "Hello!",
				CreatedAt:     now,
			},
			wantErr: true,
			errMsg:  "invalid lexicon type",
		},
		{
			name: "text too long (bytes)",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          strings.Repeat("a", 10001),
				CreatedAt:     now,
			},
			wantErr: true,
			errMsg:  "text field exceeds maximum length of 10000 bytes",
		},
		{
			name: "text too long (graphemes)",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          strings.Repeat("a", 3001),
				CreatedAt:     now,
			},
			wantErr: true,
			errMsg:  "text field exceeds maximum of 3000 characters",
		},
		{
			name: "max valid text length (bytes, ASCII)",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          strings.Repeat("a", 3000),
				CreatedAt:     now,
			},
			wantErr: false,
		},
		{
			name: "max valid text length (graphemes with emoji)",
			record: &DemoRecord{
				LexiconTypeID: "com.demo.bskyoauth",
				Text:          strings.Repeat("😀", 2500), // 2500 emojis = 10000 bytes, under grapheme limit
				CreatedAt:     now,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.record.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Validate() error = %v, should contain %q", err, tt.errMsg)
			}
		})
	}
}
