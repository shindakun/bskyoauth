package bskyoauth

import (
	"io"

	"github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

// CustomRecord wraps a map to make it compatible with CBOR marshaling.
type CustomRecord struct {
	Data map[string]interface{}
}

// MarshalCBOR implements the CBORMarshaler interface.
func (r *CustomRecord) MarshalCBOR(w io.Writer) error {
	// Write the map length
	if err := cbg.WriteMajorTypeHeader(w, cbg.MajMap, uint64(len(r.Data))); err != nil {
		return err
	}

	// Write each key-value pair
	for k, v := range r.Data {
		// Write the key (as text string)
		if err := cbg.WriteMajorTypeHeader(w, cbg.MajTextString, uint64(len(k))); err != nil {
			return err
		}
		if _, err := w.Write([]byte(k)); err != nil {
			return err
		}

		// Write the value
		if err := writeValue(w, v); err != nil {
			return err
		}
	}

	return nil
}

// writeValue writes a value based on its type
func writeValue(w io.Writer, v interface{}) error {
	switch val := v.(type) {
	case string:
		if err := cbg.WriteMajorTypeHeader(w, cbg.MajTextString, uint64(len(val))); err != nil {
			return err
		}
		_, err := w.Write([]byte(val))
		return err
	case int:
		return cbg.WriteMajorTypeHeader(w, cbg.MajUnsignedInt, uint64(val))
	case int64:
		return cbg.WriteMajorTypeHeader(w, cbg.MajUnsignedInt, uint64(val))
	case uint64:
		return cbg.WriteMajorTypeHeader(w, cbg.MajUnsignedInt, val)
	case bool:
		return cbg.WriteBool(w, val)
	case []byte:
		return cbg.WriteByteArray(w, val)
	case cid.Cid:
		return cbg.WriteCid(w, val)
	case map[string]interface{}:
		// Nested map
		rec := &CustomRecord{Data: val}
		return rec.MarshalCBOR(w)
	case []interface{}:
		// Array
		if err := cbg.WriteMajorTypeHeader(w, cbg.MajArray, uint64(len(val))); err != nil {
			return err
		}
		for _, item := range val {
			if err := writeValue(w, item); err != nil {
				return err
			}
		}
		return nil
	default:
		// For other types, try to write as string
		if err := cbg.WriteMajorTypeHeader(w, cbg.MajTextString, uint64(0)); err != nil {
			return err
		}
		return nil
	}
}

// UnmarshalCBOR implements the CBORUnmarshaler interface.
func (r *CustomRecord) UnmarshalCBOR(reader io.Reader) error {
	// Not implemented for now as we only need to write records
	return nil
}
