package bskyoauth

import (
	"bytes"
	"testing"

	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func TestCustomRecord_MarshalCBOR_EmptyMap(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal empty map: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer for empty map")
	}
}

func TestCustomRecord_MarshalCBOR_StringValue(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"text": "hello world",
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal string value: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_IntValue(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"count": 42,
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal int value: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_Int64Value(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"bigNumber": int64(9223372036854775807),
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal int64 value: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_Uint64Value(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"unsignedBig": uint64(18446744073709551615),
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal uint64 value: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_BoolValue(t *testing.T) {
	testCases := []struct {
		name  string
		value bool
	}{
		{"true value", true},
		{"false value", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			record := &CustomRecord{
				Data: map[string]interface{}{
					"flag": tc.value,
				},
			}

			var buf bytes.Buffer
			err := record.MarshalCBOR(&buf)
			if err != nil {
				t.Fatalf("Failed to marshal bool value: %v", err)
			}

			if buf.Len() == 0 {
				t.Error("Expected non-empty buffer")
			}
		})
	}
}

func TestCustomRecord_MarshalCBOR_ByteArrayValue(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"bytes": []byte{0x01, 0x02, 0x03, 0x04},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal byte array: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_CIDValue(t *testing.T) {
	// Create a test CID (using CIDv1 with raw codec)
	testCID := cid.NewCidV1(cid.Raw, []byte("test hash data for cid"))

	record := &CustomRecord{
		Data: map[string]interface{}{
			"link": testCID,
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal CID value: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_NestedMap(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"user": map[string]interface{}{
				"name": "Alice",
				"age":  30,
			},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal nested map: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_Array(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"tags": []interface{}{"golang", "cbor", "testing"},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal array: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_MixedArray(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"mixed": []interface{}{"string", 42, true, []byte{0xFF}},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal mixed array: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_NestedArray(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"matrix": []interface{}{
				[]interface{}{1, 2, 3},
				[]interface{}{4, 5, 6},
			},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal nested array: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_ComplexStructure(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"type":      "post",
			"createdAt": "2024-01-01T00:00:00Z",
			"text":      "Hello, world!",
			"likes":     100,
			"verified":  true,
			"metadata": map[string]interface{}{
				"source": "web",
				"tags":   []interface{}{"announcement", "important"},
			},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal complex structure: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_MultipleFields(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"field1": "value1",
			"field2": 42,
			"field3": true,
			"field4": []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal multiple fields: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}

	// Verify we wrote data for a map with 4 entries
	// CBOR map with 4 entries should start with 0xa4 (major type 5, additional info 4)
	firstByte := buf.Bytes()[0]
	majorType := firstByte >> 5
	if majorType != cbg.MajMap {
		t.Errorf("Expected major type %d (map), got %d", cbg.MajMap, majorType)
	}
}

func TestCustomRecord_MarshalCBOR_UnknownType(t *testing.T) {
	// Test with an unsupported type (should write empty string)
	type unknownType struct {
		Value string
	}

	record := &CustomRecord{
		Data: map[string]interface{}{
			"unknown": unknownType{Value: "test"},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal with unknown type: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_EmptyString(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"empty": "",
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal empty string: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_EmptyArray(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"emptyList": []interface{}{},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal empty array: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_EmptyNestedMap(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"nested": map[string]interface{}{},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal empty nested map: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_LargeString(t *testing.T) {
	// Test with a large string (>1KB)
	data := make([]byte, 2048)
	for i := range data {
		data[i] = 'a'
	}
	largeString := string(data)

	record := &CustomRecord{
		Data: map[string]interface{}{
			"large": largeString,
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal large string: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_DeepNesting(t *testing.T) {
	// Test deeply nested structure
	record := &CustomRecord{
		Data: map[string]interface{}{
			"level1": map[string]interface{}{
				"level2": map[string]interface{}{
					"level3": map[string]interface{}{
						"value": "deep",
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal deep nesting: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_SpecialCharacters(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"unicode": "Hello 世界 🌍",
			"symbols": "!@#$%^&*()",
			"quotes":  `"'`,
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal special characters: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_UnmarshalCBOR(t *testing.T) {
	// UnmarshalCBOR is not implemented, should return nil
	record := &CustomRecord{}
	var buf bytes.Buffer

	err := record.UnmarshalCBOR(&buf)
	if err != nil {
		t.Errorf("Expected nil error from unimplemented UnmarshalCBOR, got: %v", err)
	}
}

func TestCustomRecord_MarshalCBOR_ZeroValues(t *testing.T) {
	record := &CustomRecord{
		Data: map[string]interface{}{
			"zeroInt":    0,
			"zeroInt64":  int64(0),
			"zeroUint64": uint64(0),
			"falseBool":  false,
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal zero values: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}
}

func TestCustomRecord_MarshalCBOR_RealWorldExample(t *testing.T) {
	// Simulate a real Bluesky post record
	record := &CustomRecord{
		Data: map[string]interface{}{
			"$type":     "app.bsky.feed.post",
			"text":      "Testing CBOR marshaling for Bluesky posts!",
			"createdAt": "2024-01-15T12:00:00.000Z",
			"langs":     []interface{}{"en"},
			"facets": []interface{}{
				map[string]interface{}{
					"index": map[string]interface{}{
						"byteStart": 0,
						"byteEnd":   7,
					},
					"features": []interface{}{
						map[string]interface{}{
							"$type": "app.bsky.richtext.facet#tag",
							"tag":   "testing",
						},
					},
				},
			},
		},
	}

	var buf bytes.Buffer
	err := record.MarshalCBOR(&buf)
	if err != nil {
		t.Fatalf("Failed to marshal real-world example: %v", err)
	}

	if buf.Len() == 0 {
		t.Error("Expected non-empty buffer")
	}

	// Verify the buffer contains valid CBOR data
	// First byte should be a map (major type 5)
	if buf.Len() > 0 {
		firstByte := buf.Bytes()[0]
		majorType := firstByte >> 5
		if majorType != cbg.MajMap {
			t.Errorf("Expected CBOR to start with map (major type %d), got major type %d", cbg.MajMap, majorType)
		}
	}
}
