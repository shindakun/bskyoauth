package lexicon

import (
	"fmt"
	"time"
	"unicode/utf8"
)

// Validate checks if the DemoRecord has valid field values
func (d *DemoRecord) Validate() error {
	if d == nil {
		return fmt.Errorf("record cannot be nil")
	}

	// Validate LexiconTypeID
	if d.LexiconTypeID != "com.demo.bskyoauth" {
		return fmt.Errorf("invalid lexicon type: expected 'com.demo.bskyoauth', got '%s'", d.LexiconTypeID)
	}

	// Validate Text field
	if d.Text == "" {
		return fmt.Errorf("text field is required")
	}

	if len(d.Text) > 10000 {
		return fmt.Errorf("text field exceeds maximum length of 10000 bytes (got %d)", len(d.Text))
	}

	// Count graphemes (runes) for Unicode support
	graphemeCount := utf8.RuneCountInString(d.Text)
	if graphemeCount > 3000 {
		return fmt.Errorf("text field exceeds maximum of 3000 characters (got %d)", graphemeCount)
	}

	// Validate CreatedAt field
	if d.CreatedAt == "" {
		return fmt.Errorf("createdAt field is required")
	}

	// Validate RFC3339 format
	_, err := time.Parse(time.RFC3339, d.CreatedAt)
	if err != nil {
		return fmt.Errorf("createdAt must be valid RFC3339 timestamp: %w", err)
	}

	return nil
}
