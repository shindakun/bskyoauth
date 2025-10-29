package bskyoauth

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// Validation error types
var (
	ErrHandleInvalid      = errors.New("handle format is invalid")
	ErrHandleTooLong      = errors.New("handle exceeds maximum length")
	ErrTextEmpty          = errors.New("text cannot be empty")
	ErrTextTooLong        = errors.New("text exceeds maximum length")
	ErrInvalidUTF8        = errors.New("text contains invalid UTF-8")
	ErrNullByte           = errors.New("text contains null bytes")
	ErrRecordFieldInvalid = errors.New("record field is invalid")
	ErrInvalidDatetime    = errors.New("datetime format is invalid")
	ErrInvalidCollection  = errors.New("collection NSID is invalid")
)

const (
	// MaxPostTextLength is the maximum length for post text per AT Protocol spec
	MaxPostTextLength = 300
	// MaxHandleLength is the maximum length for handles per AT Protocol spec
	MaxHandleLength = 253
	// MaxHandleSegmentLength is the maximum length for a single handle segment
	MaxHandleSegmentLength = 63
)

// ValidateHandle validates a Bluesky handle against AT Protocol specifications.
// Handles must be valid domain names with specific constraints:
// - Maximum 253 characters total
// - Each segment (between dots) maximum 63 characters
// - Only lowercase letters, digits, and hyphens allowed
// - No trailing or leading dots
// - TLD cannot start with a digit
func ValidateHandle(handle string) error {
	if handle == "" {
		return fmt.Errorf("%w: handle is empty", ErrHandleInvalid)
	}

	// Use the AT Protocol syntax package for validation
	_, err := syntax.ParseHandle(handle)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHandleInvalid, err)
	}

	return nil
}

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

// ValidateRecordFields validates common fields in a record map.
// This performs basic validation on standard fields like createdAt.
func ValidateRecordFields(record map[string]interface{}) error {
	if record == nil {
		return fmt.Errorf("%w: record is nil", ErrRecordFieldInvalid)
	}

	// Validate createdAt field if present
	if createdAt, exists := record["createdAt"]; exists {
		createdAtStr, ok := createdAt.(string)
		if !ok {
			return fmt.Errorf("%w: createdAt must be a string", ErrRecordFieldInvalid)
		}

		// Validate datetime format using AT Protocol syntax package
		_, err := syntax.ParseDatetime(createdAtStr)
		if err != nil {
			return fmt.Errorf("%w: createdAt format invalid: %v", ErrInvalidDatetime, err)
		}
	}

	// Validate text field if present (common in many record types)
	if text, exists := record["text"]; exists {
		textStr, ok := text.(string)
		if !ok {
			return fmt.Errorf("%w: text field must be a string", ErrRecordFieldInvalid)
		}

		// Use a generous limit for custom records (1000 chars)
		// Individual applications can apply stricter limits
		if err := ValidateTextField(textStr, "text", 1000); err != nil {
			return err
		}
	}

	// Check for excessively deep nesting or large structures
	// This is a simple check to prevent memory exhaustion
	if err := validateRecordDepth(record, 0, 10); err != nil {
		return err
	}

	return nil
}

// validateRecordDepth recursively checks record depth to prevent stack overflow
// and memory exhaustion from deeply nested structures
func validateRecordDepth(value interface{}, currentDepth, maxDepth int) error {
	if currentDepth > maxDepth {
		return fmt.Errorf("%w: record nesting too deep (max %d levels)", ErrRecordFieldInvalid, maxDepth)
	}

	switch v := value.(type) {
	case map[string]interface{}:
		for _, val := range v {
			if err := validateRecordDepth(val, currentDepth+1, maxDepth); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, val := range v {
			if err := validateRecordDepth(val, currentDepth+1, maxDepth); err != nil {
				return err
			}
		}
	}

	return nil
}

// ValidateCollectionNSID validates that a collection name is a valid NSID.
// NSIDs are Namespaced Identifiers used in the AT Protocol to identify
// record types (e.g., "app.bsky.feed.post").
func ValidateCollectionNSID(collection string) error {
	if collection == "" {
		return fmt.Errorf("%w: collection is empty", ErrInvalidCollection)
	}

	_, err := syntax.ParseNSID(collection)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCollection, err)
	}

	return nil
}
