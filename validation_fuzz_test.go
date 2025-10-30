package bskyoauth

import (
	"strings"
	"testing"
)

// FuzzValidateHandle tests handle validation with random inputs.
func FuzzValidateHandle(f *testing.F) {
	// Seed corpus with known good/bad inputs
	f.Add("alice.bsky.social")
	f.Add("test.example.com")
	f.Add("a")
	f.Add(strings.Repeat("a", 254))
	f.Add("invalid..handle")
	f.Add(".invalid")
	f.Add("invalid.")
	f.Add("test-123.example-456.com")

	f.Fuzz(func(t *testing.T, handle string) {
		// Should never panic
		_ = ValidateHandle(handle)
	})
}

// FuzzValidatePostText tests post text validation with random inputs.
func FuzzValidatePostText(f *testing.F) {
	// Seed corpus with known inputs
	f.Add("Hello, world!")
	f.Add("")
	f.Add(strings.Repeat("a", 301))
	f.Add("Test with emoji 🚀")
	f.Add("Test with null\x00byte")
	f.Add(strings.Repeat("👍", 150))

	f.Fuzz(func(t *testing.T, text string) {
		// Should never panic
		_ = ValidatePostText(text)
	})
}

// FuzzValidateTextField tests generic text field validation.
func FuzzValidateTextField(f *testing.F) {
	// Seed corpus
	f.Add("test text", "field", 100)
	f.Add("", "empty", 10)
	f.Add(strings.Repeat("a", 1000), "long", 500)

	f.Fuzz(func(t *testing.T, text string, fieldName string, maxLength int) {
		// Limit maxLength to reasonable values to prevent OOM
		if maxLength < 0 || maxLength > 100000 {
			return
		}
		// Should never panic
		_ = ValidateTextField(text, fieldName, maxLength)
	})
}

// FuzzValidateCollectionNSID tests NSID validation with random inputs.
func FuzzValidateCollectionNSID(f *testing.F) {
	// Seed corpus
	f.Add("app.bsky.feed.post")
	f.Add("com.example.test")
	f.Add("invalid")
	f.Add("invalid..nsid")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, collection string) {
		// Should never panic
		_ = ValidateCollectionNSID(collection)
	})
}

// FuzzValidateRecordFields tests record validation with random map data.
func FuzzValidateRecordFields(f *testing.F) {
	// Seed corpus with RFC3339 timestamps
	f.Add("2023-01-01T00:00:00Z")
	f.Add("invalid-date")
	f.Add("")

	f.Fuzz(func(t *testing.T, createdAt string) {
		record := map[string]interface{}{
			"createdAt": createdAt,
			"text":      "test",
		}
		// Should never panic
		_ = ValidateRecordFields(record)
	})
}
