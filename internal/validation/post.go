package validation

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Post validation errors
var (
	ErrTextEmpty   = errors.New("text cannot be empty")
	ErrTextTooLong = errors.New("text exceeds maximum length")
	ErrInvalidUTF8 = errors.New("text contains invalid UTF-8")
	ErrNullByte    = errors.New("text contains null bytes")
)

const (
	// MaxPostTextLength is the maximum length for post text per AT Protocol spec
	MaxPostTextLength = 300
)

// ValidatePostText validates text for a Bluesky post.
// Text must be:
// - Non-empty
// - Maximum 300 characters (grapheme clusters/runes)
// - Valid UTF-8
// - No null bytes
func ValidatePostText(text string) error {
	if text == "" {
		return ErrTextEmpty
	}

	// Check for null bytes
	if bytes.ContainsRune([]byte(text), 0) {
		return ErrNullByte
	}

	// Validate UTF-8
	if !utf8.ValidString(text) {
		return ErrInvalidUTF8
	}

	// Count runes (grapheme clusters approximation)
	// Note: This counts Unicode code points, which is close enough for most cases
	// A full grapheme cluster implementation would require a more complex library
	runeCount := utf8.RuneCountInString(text)
	if runeCount > MaxPostTextLength {
		return fmt.Errorf("%w: %d characters (max %d)", ErrTextTooLong, runeCount, MaxPostTextLength)
	}

	// Check for whitespace-only text
	if strings.TrimSpace(text) == "" {
		return ErrTextEmpty
	}

	return nil
}

// ValidateTextField validates a generic text field with custom length limits.
// This is useful for custom record fields that have different length requirements.
func ValidateTextField(text string, fieldName string, maxLength int) error {
	if text == "" {
		return fmt.Errorf("%w: field '%s' is empty", ErrTextEmpty, fieldName)
	}

	// Check for null bytes
	if bytes.ContainsRune([]byte(text), 0) {
		return fmt.Errorf("%w: field '%s' contains null bytes", ErrNullByte, fieldName)
	}

	// Validate UTF-8
	if !utf8.ValidString(text) {
		return fmt.Errorf("%w: field '%s' contains invalid UTF-8", ErrInvalidUTF8, fieldName)
	}

	// Count runes
	runeCount := utf8.RuneCountInString(text)
	if runeCount > maxLength {
		return fmt.Errorf("%w: field '%s' has %d characters (max %d)", ErrTextTooLong, fieldName, runeCount, maxLength)
	}

	return nil
}
