# Implementation Plan for Issue #9: Input Validation and Sanitization

Based on analysis of the codebase and AT Protocol specifications, here's a comprehensive plan to implement input validation and sanitization.

## Overview
Add comprehensive input validation to prevent injection attacks, resource exhaustion, and API errors. The implementation will leverage existing AT Protocol validation libraries where possible and add custom validation for application-specific constraints.

## 1. Create New Validation Module (`validation.go`)

**Purpose**: Centralized validation functions for reusability across the codebase.

**Functions to implement**:

### a) Handle Validation
```go
func ValidateHandle(handle string) error
```
- Use `syntax.ParseHandle()` from indigo package (already available)
- Returns descriptive error if handle format is invalid
- Validates: length (max 253 chars), segment length (1-63 chars), allowed characters (a-z, 0-9, hyphen), no trailing dots, TLD cannot start with digit

### b) Post Text Validation
```go
func ValidatePostText(text string) error
```
- Check length: 1-300 grapheme clusters (AT Protocol spec limit)
- Use `utf8.RuneCountInString()` for accurate character counting
- Validate text is not empty (already partially done)
- Check for null bytes or invalid UTF-8

### c) Generic Text Field Validation
```go
func ValidateTextField(text string, fieldName string, maxLength int) error
```
- Reusable for custom record fields
- Validate length and UTF-8 encoding
- Return descriptive errors with field name

### d) Record Field Validation
```go
func ValidateRecordFields(record map[string]interface{}) error
```
- Validate common fields like `createdAt` (must be valid datetime)
- Check for required `$type` field if needed
- Validate field value types match expectations
- Size limits for nested structures to prevent memory exhaustion

## 2. Update `client.go`

### a) Modify `LoginHandler()` (lines 285-303)
**Current**: Only checks if handle is empty
**New**: Add handle format validation using `ValidateHandle()`

```go
handle := r.URL.Query().Get("handle")
if handle == "" {
    http.Error(w, "handle parameter required", http.StatusBadRequest)
    return
}

// NEW: Validate handle format
if err := ValidateHandle(handle); err != nil {
    http.Error(w, fmt.Sprintf("invalid handle: %v", err), http.StatusBadRequest)
    return
}
```

### b) Modify `CreatePost()` (lines 97-153)
**Current**: No validation on text parameter
**New**: Add text validation before processing

```go
func (c *Client) CreatePost(ctx context.Context, session *Session, text string) error {
    if session == nil || session.AccessToken == "" {
        return ErrNoSession
    }

    // NEW: Validate post text
    if err := ValidatePostText(text); err != nil {
        return fmt.Errorf("invalid post text: %w", err)
    }

    // ... rest of function
}
```

### c) Modify `CreateRecord()` (lines 156-215)
**Current**: No validation on record data
**New**: Add record validation

```go
func (c *Client) CreateRecord(ctx context.Context, session *Session, collection string, record map[string]interface{}) (*atproto.RepoCreateRecord_Output, error) {
    if session == nil || session.AccessToken == "" {
        return nil, ErrNoSession
    }

    // NEW: Validate collection is a valid NSID
    if _, err := syntax.ParseNSID(collection); err != nil {
        return nil, fmt.Errorf("invalid collection NSID: %w", err)
    }

    // NEW: Validate record fields
    if err := ValidateRecordFields(record); err != nil {
        return nil, fmt.Errorf("invalid record: %w", err)
    }

    // ... rest of function
}
```

## 3. Update `examples/web-demo/main.go`

### a) Modify `postHandler()` (lines 162-191)
**Current**: Only checks if text is empty
**New**: Validate text before calling CreatePost

```go
text := r.FormValue("text")
if text == "" {
    http.Error(w, "Text is required", http.StatusBadRequest)
    return
}

// NEW: Validate post text length and content
if err := bskyoauth.ValidatePostText(text); err != nil {
    http.Error(w, fmt.Sprintf("Invalid post text: %v", err), http.StatusBadRequest)
    return
}
```

### b) Modify `createOngakuHandler()` (lines 193-232)
**Current**: Only checks if text is empty
**New**: Validate text and record structure

```go
text := r.FormValue("text")
if text == "" {
    http.Error(w, "Text is required", http.StatusBadRequest)
    return
}

// NEW: Validate text field for custom record
if err := bskyoauth.ValidateTextField(text, "text", 1000); err != nil {
    http.Error(w, fmt.Sprintf("Invalid text: %v", err), http.StatusBadRequest)
    return
}

record := map[string]interface{}{
    "text":      text,
    "createdAt": time.Now().Format(time.RFC3339),
}
```

## 4. Add Comprehensive Error Types

Create new error variables in validation.go:

```go
var (
    ErrHandleInvalid      = errors.New("handle format is invalid")
    ErrHandleTooLong      = errors.New("handle exceeds maximum length")
    ErrTextEmpty          = errors.New("text cannot be empty")
    ErrTextTooLong        = errors.New("text exceeds maximum length")
    ErrInvalidUTF8        = errors.New("text contains invalid UTF-8")
    ErrNullByte           = errors.New("text contains null bytes")
    ErrRecordFieldInvalid = errors.New("record field is invalid")
)
```

## 5. Create Comprehensive Test Suite (`validation_test.go`)

**Test cases** (minimum 30 tests):

### Handle Validation Tests (10 tests)
- Valid handles (alice.bsky.social, user123.example.com)
- Empty handle
- Handle too long (>253 chars)
- Segment too long (>63 chars)
- Invalid characters (spaces, underscores, special chars)
- Trailing/leading dots
- TLD starting with digit
- Uppercase letters (should normalize)
- IP addresses (should reject)

### Post Text Validation Tests (10 tests)
- Valid text (various lengths: 1, 150, 300 chars)
- Empty text
- Text too long (301+ chars)
- Text with emojis (counts correctly as graphemes)
- Text with unicode (various scripts)
- Text with null bytes
- Invalid UTF-8
- Whitespace-only text
- Very long single line

### Generic Text Field Tests (5 tests)
- Valid text within limits
- Text exceeding custom limit
- Empty text
- Invalid UTF-8
- Null bytes

### Record Field Validation Tests (5 tests)
- Valid record with all required fields
- Record with invalid createdAt format
- Record with missing fields
- Record with oversized nested structures
- Record with invalid field types

## 6. Update Error Handling Documentation

Add section to README.md explaining validation errors:

```markdown
### Input Validation

The library performs comprehensive input validation to prevent errors and security issues:

- **Handles**: Validated against AT Protocol handle specification (max 253 chars, valid format)
- **Post Text**: Limited to 300 characters per AT Protocol spec
- **Custom Records**: Field-level validation with configurable limits
- **Collection Names**: Must be valid NSIDs

All validation errors return descriptive error messages.
```

## 7. Update CHANGELOG.md

```markdown
### Added
- Comprehensive input validation module (validation.go)
- Handle format validation using AT Protocol syntax package
- Post text length validation (300 character limit per spec)
- Generic text field validation with configurable limits
- Record field validation for custom records
- Collection NSID validation
- 30+ validation test cases

### Changed
- LoginHandler now validates handle format before starting OAuth flow
- CreatePost now validates text length and content
- CreateRecord now validates collection NSID and record fields
- Web-demo examples now validate all user inputs before API calls

### Security
- Prevents resource exhaustion via length limit enforcement
- Prevents injection attacks via input sanitization
- Validates UTF-8 encoding to prevent encoding attacks
- Rejects null bytes and invalid characters
```

## 8. Implementation Order

1. **Step 1**: Create `validation.go` with all validation functions (export for library users)
2. **Step 2**: Create `validation_test.go` with comprehensive tests (TDD approach)
3. **Step 3**: Update `client.go` to use validation functions
4. **Step 4**: Update `examples/web-demo/main.go` to use validation
5. **Step 5**: Run all tests and ensure 100% pass rate
6. **Step 6**: Update documentation (README.md, CHANGELOG.md)
7. **Step 7**: Update TODO.md to mark issue #9 as completed
8. **Step 8**: Commit changes with descriptive message

## Expected Impact

- **Security**: Prevents injection attacks, resource exhaustion, encoding attacks
- **Reliability**: Catches errors early before API calls, reducing failed requests
- **User Experience**: Provides clear, actionable error messages
- **Maintainability**: Centralized validation logic for easy updates
- **Compliance**: Enforces AT Protocol specifications

## Testing Strategy

- Run existing test suite to ensure no regressions (currently 127 tests)
- Add 30+ new validation tests
- Test edge cases (empty, max length, max+1, unicode, emojis)
- Test error messages are descriptive and actionable
- Manual testing with web-demo to verify user-facing errors

## Estimated Changes

- **New files**: 2 (validation.go ~200 lines, validation_test.go ~400 lines)
- **Modified files**: 3 (client.go +15 lines, main.go +10 lines, README.md +20 lines)
- **Total new tests**: 30+
- **Expected test coverage increase**: validation.go should achieve 95%+ coverage

## Notes

- Leverages existing `github.com/bluesky-social/indigo/atproto/syntax` package for handle/NSID validation
- Follows AT Protocol specifications for all limits (300 char posts, 253 char handles)
- Provides library-level validation that users can call directly
- Maintains backward compatibility - validation happens before API calls
- All validation functions return descriptive errors for debugging
