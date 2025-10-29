package bskyoauth

import (
	"github.com/shindakun/bskyoauth/internal/validation"
)

// Re-export validation error types for backward compatibility
var (
	ErrHandleInvalid      = validation.ErrHandleInvalid
	ErrHandleTooLong      = validation.ErrHandleTooLong
	ErrTextEmpty          = validation.ErrTextEmpty
	ErrTextTooLong        = validation.ErrTextTooLong
	ErrInvalidUTF8        = validation.ErrInvalidUTF8
	ErrNullByte           = validation.ErrNullByte
	ErrRecordFieldInvalid = validation.ErrRecordFieldInvalid
	ErrInvalidDatetime    = validation.ErrInvalidDatetime
	ErrInvalidCollection  = validation.ErrInvalidCollection
)

// Re-export validation constants for backward compatibility
const (
	MaxPostTextLength      = validation.MaxPostTextLength
	MaxHandleLength        = validation.MaxHandleLength
	MaxHandleSegmentLength = validation.MaxHandleSegmentLength
)

// ValidateHandle validates a Bluesky handle against AT Protocol specifications.
// Handles must be valid domain names with specific constraints:
// - Maximum 253 characters total
// - Each segment (between dots) maximum 63 characters
// - Only lowercase letters, digits, and hyphens allowed
// - No trailing or leading dots
// - TLD cannot start with a digit
func ValidateHandle(handle string) error {
	return validation.ValidateHandle(handle)
}

// ValidatePostText validates text for a Bluesky post.
// Text must be:
// - Non-empty
// - Maximum 300 characters (grapheme clusters/runes)
// - Valid UTF-8
// - No null bytes
func ValidatePostText(text string) error {
	return validation.ValidatePostText(text)
}

// ValidateTextField validates a generic text field with custom length limits.
// This is useful for custom record fields that have different length requirements.
func ValidateTextField(text string, fieldName string, maxLength int) error {
	return validation.ValidateTextField(text, fieldName, maxLength)
}

// ValidateRecordFields validates common fields in a record map.
// This performs basic validation on standard fields like createdAt.
func ValidateRecordFields(record map[string]interface{}) error {
	return validation.ValidateRecordFields(record)
}

// ValidateCollectionNSID validates that a collection name is a valid NSID.
// NSIDs are Namespaced Identifiers used in the AT Protocol to identify
// record types (e.g., "app.bsky.feed.post").
func ValidateCollectionNSID(collection string) error {
	return validation.ValidateCollectionNSID(collection)
}
