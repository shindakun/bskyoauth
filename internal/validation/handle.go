package validation

import (
	"errors"
	"fmt"

	"github.com/bluesky-social/indigo/atproto/syntax"
)

// Handle validation errors
var (
	ErrHandleInvalid = errors.New("handle format is invalid")
	ErrHandleTooLong = errors.New("handle exceeds maximum length")
)

const (
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
