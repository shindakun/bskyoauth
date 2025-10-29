package validation

import (
	"errors"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// Record validation errors
var (
	ErrRecordFieldInvalid = errors.New("record field is invalid")
	ErrInvalidDatetime    = errors.New("datetime format is invalid")
	ErrInvalidCollection  = errors.New("collection NSID is invalid")
)

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
