package bskyoauth

import (
	"strings"
	"testing"
)

// TestValidateHandle_ValidHandles tests valid handle formats
func TestValidateHandle_ValidHandles(t *testing.T) {
	validHandles := []string{
		"alice.bsky.social",
		"user123.example.com",
		"test-user.domain.com",
		"a.b.c.d.e.example.org",
		"123user.example.com", // segment can start with digit (except TLD)
		"user-name.test.io",
	}

	for _, handle := range validHandles {
		t.Run(handle, func(t *testing.T) {
			err := ValidateHandle(handle)
			if err != nil {
				t.Errorf("ValidateHandle(%q) returned error: %v, want nil", handle, err)
			}
		})
	}
}

// TestValidateHandle_EmptyHandle tests empty handle validation
func TestValidateHandle_EmptyHandle(t *testing.T) {
	err := ValidateHandle("")
	if err == nil {
		t.Error("ValidateHandle(\"\") returned nil, want error")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("ValidateHandle(\"\") error = %v, want error containing 'empty'", err)
	}
}

// TestValidateHandle_TooLong tests handle exceeding max length
func TestValidateHandle_TooLong(t *testing.T) {
	// Create a handle longer than 253 characters
	longHandle := strings.Repeat("a", 250) + ".com"
	err := ValidateHandle(longHandle)
	if err == nil {
		t.Errorf("ValidateHandle(long handle) returned nil, want error")
	}
}

// TestValidateHandle_SegmentTooLong tests handle segment exceeding 63 chars
func TestValidateHandle_SegmentTooLong(t *testing.T) {
	// Create a segment longer than 63 characters
	longSegment := strings.Repeat("a", 64) + ".example.com"
	err := ValidateHandle(longSegment)
	if err == nil {
		t.Errorf("ValidateHandle(segment too long) returned nil, want error")
	}
}

// TestValidateHandle_InvalidCharacters tests handles with invalid characters
func TestValidateHandle_InvalidCharacters(t *testing.T) {
	invalidHandles := []string{
		"user name.example.com", // space
		"user_name.example.com", // underscore
		"user@example.com",      // @ symbol
		"user!.example.com",     // exclamation
		"user#name.example.com", // hash
		"user.example..com",     // consecutive dots
	}

	for _, handle := range invalidHandles {
		t.Run(handle, func(t *testing.T) {
			err := ValidateHandle(handle)
			if err == nil {
				t.Errorf("ValidateHandle(%q) returned nil, want error", handle)
			}
		})
	}
}

// TestValidateHandle_TrailingDot tests handle with trailing dot
func TestValidateHandle_TrailingDot(t *testing.T) {
	err := ValidateHandle("user.example.com.")
	if err == nil {
		t.Error("ValidateHandle(trailing dot) returned nil, want error")
	}
}

// TestValidateHandle_LeadingDot tests handle with leading dot
func TestValidateHandle_LeadingDot(t *testing.T) {
	err := ValidateHandle(".user.example.com")
	if err == nil {
		t.Error("ValidateHandle(leading dot) returned nil, want error")
	}
}

// TestValidateHandle_TLDStartsWithDigit tests TLD starting with digit
func TestValidateHandle_TLDStartsWithDigit(t *testing.T) {
	err := ValidateHandle("user.example.123")
	if err == nil {
		t.Error("ValidateHandle(TLD starts with digit) returned nil, want error")
	}
}

// TestValidateHandle_IPAddress tests IP addresses (should be rejected)
func TestValidateHandle_IPAddress(t *testing.T) {
	ipAddresses := []string{
		"192.168.1.1",
		"10.0.0.1",
	}

	for _, ip := range ipAddresses {
		t.Run(ip, func(t *testing.T) {
			err := ValidateHandle(ip)
			if err == nil {
				t.Errorf("ValidateHandle(%q) returned nil, want error", ip)
			}
		})
	}
}

// TestValidatePostText_ValidText tests valid post text
func TestValidatePostText_ValidText(t *testing.T) {
	validTexts := []struct {
		name string
		text string
	}{
		{"single char", "a"},
		{"normal text", "Hello, world!"},
		{"150 chars", strings.Repeat("a", 150)},
		{"300 chars", strings.Repeat("a", 300)},
		{"with emojis", "Hello 👋 world 🌍"},
		{"with unicode", "Привет мир 你好世界"},
		{"with newlines", "Line 1\nLine 2\nLine 3"},
	}

	for _, tc := range validTexts {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePostText(tc.text)
			if err != nil {
				t.Errorf("ValidatePostText(%q) returned error: %v, want nil", tc.text, err)
			}
		})
	}
}

// TestValidatePostText_EmptyText tests empty text validation
func TestValidatePostText_EmptyText(t *testing.T) {
	err := ValidatePostText("")
	if err != ErrTextEmpty {
		t.Errorf("ValidatePostText(\"\") = %v, want %v", err, ErrTextEmpty)
	}
}

// TestValidatePostText_WhitespaceOnly tests whitespace-only text
func TestValidatePostText_WhitespaceOnly(t *testing.T) {
	whitespaceTexts := []string{
		" ",
		"   ",
		"\t",
		"\n",
		" \t\n ",
	}

	for _, text := range whitespaceTexts {
		t.Run("whitespace", func(t *testing.T) {
			err := ValidatePostText(text)
			if err != ErrTextEmpty {
				t.Errorf("ValidatePostText(whitespace) = %v, want %v", err, ErrTextEmpty)
			}
		})
	}
}

// TestValidatePostText_TooLong tests text exceeding 300 characters
func TestValidatePostText_TooLong(t *testing.T) {
	longText := strings.Repeat("a", 301)
	err := ValidatePostText(longText)
	if err == nil {
		t.Error("ValidatePostText(301 chars) returned nil, want error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("ValidatePostText(301 chars) error = %v, want error containing 'exceeds'", err)
	}
}

// TestValidatePostText_WithEmojis tests emoji counting
func TestValidatePostText_WithEmojis(t *testing.T) {
	// Emojis can be multiple bytes but count as single characters
	text := strings.Repeat("👋", 300)
	err := ValidatePostText(text)
	if err != nil {
		t.Errorf("ValidatePostText(300 emojis) returned error: %v, want nil", err)
	}

	// 301 emojis should fail
	longText := strings.Repeat("👋", 301)
	err = ValidatePostText(longText)
	if err == nil {
		t.Error("ValidatePostText(301 emojis) returned nil, want error")
	}
}

// TestValidatePostText_NullByte tests text with null bytes
func TestValidatePostText_NullByte(t *testing.T) {
	textWithNull := "Hello\x00World"
	err := ValidatePostText(textWithNull)
	if err != ErrNullByte {
		t.Errorf("ValidatePostText(text with null) = %v, want %v", err, ErrNullByte)
	}
}

// TestValidatePostText_InvalidUTF8 tests text with invalid UTF-8
func TestValidatePostText_InvalidUTF8(t *testing.T) {
	invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd})
	err := ValidatePostText(invalidUTF8)
	if err != ErrInvalidUTF8 {
		t.Errorf("ValidatePostText(invalid UTF-8) = %v, want %v", err, ErrInvalidUTF8)
	}
}

// TestValidateTextField_ValidText tests valid text field
func TestValidateTextField_ValidText(t *testing.T) {
	err := ValidateTextField("Hello, world!", "description", 100)
	if err != nil {
		t.Errorf("ValidateTextField(valid) returned error: %v, want nil", err)
	}
}

// TestValidateTextField_ExceedsLimit tests text exceeding custom limit
func TestValidateTextField_ExceedsLimit(t *testing.T) {
	longText := strings.Repeat("a", 101)
	err := ValidateTextField(longText, "description", 100)
	if err == nil {
		t.Error("ValidateTextField(exceeds limit) returned nil, want error")
	}
	if !strings.Contains(err.Error(), "description") {
		t.Errorf("ValidateTextField error = %v, want error containing field name", err)
	}
}

// TestValidateTextField_Empty tests empty text field
func TestValidateTextField_Empty(t *testing.T) {
	err := ValidateTextField("", "name", 100)
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("ValidateTextField(empty) = %v, want error containing 'empty'", err)
	}
}

// TestValidateTextField_InvalidUTF8 tests text field with invalid UTF-8
func TestValidateTextField_InvalidUTF8(t *testing.T) {
	invalidUTF8 := string([]byte{0xff, 0xfe, 0xfd})
	err := ValidateTextField(invalidUTF8, "field", 100)
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("ValidateTextField(invalid UTF-8) = %v, want error containing 'UTF-8'", err)
	}
}

// TestValidateTextField_NullByte tests text field with null bytes
func TestValidateTextField_NullByte(t *testing.T) {
	textWithNull := "Hello\x00World"
	err := ValidateTextField(textWithNull, "field", 100)
	if !strings.Contains(err.Error(), "null") {
		t.Errorf("ValidateTextField(null byte) = %v, want error containing 'null'", err)
	}
}

// TestValidateRecordFields_ValidRecord tests valid record
func TestValidateRecordFields_ValidRecord(t *testing.T) {
	record := map[string]interface{}{
		"text":      "Hello, world!",
		"createdAt": "2025-01-15T12:00:00.000Z",
		"other":     "data",
	}

	err := ValidateRecordFields(record)
	if err != nil {
		t.Errorf("ValidateRecordFields(valid) returned error: %v, want nil", err)
	}
}

// TestValidateRecordFields_NilRecord tests nil record
func TestValidateRecordFields_NilRecord(t *testing.T) {
	err := ValidateRecordFields(nil)
	if err == nil {
		t.Error("ValidateRecordFields(nil) returned nil, want error")
	}
}

// TestValidateRecordFields_InvalidCreatedAt tests invalid createdAt format
func TestValidateRecordFields_InvalidCreatedAt(t *testing.T) {
	record := map[string]interface{}{
		"createdAt": "invalid-date",
	}

	err := ValidateRecordFields(record)
	if err == nil {
		t.Error("ValidateRecordFields(invalid createdAt) returned nil, want error")
	}
}

// TestValidateRecordFields_CreatedAtNotString tests createdAt that's not a string
func TestValidateRecordFields_CreatedAtNotString(t *testing.T) {
	record := map[string]interface{}{
		"createdAt": 12345,
	}

	err := ValidateRecordFields(record)
	if err == nil {
		t.Error("ValidateRecordFields(createdAt not string) returned nil, want error")
	}
}

// TestValidateRecordFields_TextNotString tests text field that's not a string
func TestValidateRecordFields_TextNotString(t *testing.T) {
	record := map[string]interface{}{
		"text": 12345,
	}

	err := ValidateRecordFields(record)
	if err == nil {
		t.Error("ValidateRecordFields(text not string) returned nil, want error")
	}
}

// TestValidateRecordFields_TextTooLong tests text field exceeding limit
func TestValidateRecordFields_TextTooLong(t *testing.T) {
	record := map[string]interface{}{
		"text": strings.Repeat("a", 1001),
	}

	err := ValidateRecordFields(record)
	if err == nil {
		t.Error("ValidateRecordFields(text too long) returned nil, want error")
	}
}

// TestValidateRecordFields_DeeplyNested tests deeply nested structures
func TestValidateRecordFields_DeeplyNested(t *testing.T) {
	// Create a deeply nested structure (more than 10 levels)
	record := map[string]interface{}{}
	current := record
	for i := 0; i < 12; i++ {
		nested := map[string]interface{}{}
		current["nested"] = nested
		current = nested
	}

	err := ValidateRecordFields(record)
	if err == nil {
		t.Error("ValidateRecordFields(deeply nested) returned nil, want error")
	}
	if !strings.Contains(err.Error(), "deep") {
		t.Errorf("ValidateRecordFields(deeply nested) = %v, want error containing 'deep'", err)
	}
}

// TestValidateRecordFields_NestedArrays tests nested arrays
func TestValidateRecordFields_NestedArrays(t *testing.T) {
	record := map[string]interface{}{
		"items": []interface{}{
			map[string]interface{}{
				"name": "item1",
			},
			map[string]interface{}{
				"name": "item2",
			},
		},
	}

	err := ValidateRecordFields(record)
	if err != nil {
		t.Errorf("ValidateRecordFields(nested arrays) returned error: %v, want nil", err)
	}
}

// TestValidateCollectionNSID_ValidNSIDs tests valid NSIDs
func TestValidateCollectionNSID_ValidNSIDs(t *testing.T) {
	validNSIDs := []string{
		"app.bsky.feed.post",
		"club.ongaku.prototype",
		"com.example.record",
		"io.test.data.item",
	}

	for _, nsid := range validNSIDs {
		t.Run(nsid, func(t *testing.T) {
			err := ValidateCollectionNSID(nsid)
			if err != nil {
				t.Errorf("ValidateCollectionNSID(%q) returned error: %v, want nil", nsid, err)
			}
		})
	}
}

// TestValidateCollectionNSID_Empty tests empty NSID
func TestValidateCollectionNSID_Empty(t *testing.T) {
	err := ValidateCollectionNSID("")
	if err == nil {
		t.Error("ValidateCollectionNSID(\"\") returned nil, want error")
	}
}

// TestValidateCollectionNSID_Invalid tests invalid NSIDs
func TestValidateCollectionNSID_Invalid(t *testing.T) {
	invalidNSIDs := []string{
		"invalid",
		"no-dots-here",
		"app.bsky..post", // consecutive dots
		"app.-bsky.post", // segment starts with hyphen
	}

	for _, nsid := range invalidNSIDs {
		t.Run(nsid, func(t *testing.T) {
			err := ValidateCollectionNSID(nsid)
			if err == nil {
				t.Errorf("ValidateCollectionNSID(%q) returned nil, want error", nsid)
			}
		})
	}
}
