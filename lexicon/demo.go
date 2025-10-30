package lexicon

import (
	"fmt"
	"io"

	"github.com/bluesky-social/indigo/lex/util"
	cid "github.com/ipfs/go-cid"
	cbg "github.com/whyrusleeping/cbor-gen"
)

func init() {
	util.RegisterType("com.demo.bskyoauth", &DemoRecord{})
}

// DemoRecord represents a com.demo.bskyoauth record type.
// This is a simple demonstration record for the bskyoauth library.
type DemoRecord struct {
	// LexiconTypeID must always be "com.demo.bskyoauth"
	LexiconTypeID string `json:"$type" cborgen:"$type,const=com.demo.bskyoauth"`

	// Text is the content of the record
	Text string `json:"text" cborgen:"text"`

	// CreatedAt is the RFC3339 timestamp when the record was created
	CreatedAt string `json:"createdAt" cborgen:"createdAt"`
}

// MarshalCBOR implements cbg.CBORMarshaler for DemoRecord
func (t *DemoRecord) MarshalCBOR(w io.Writer) error {
	if t == nil {
		_, err := w.Write(cbg.CborNull)
		return err
	}

	cw := cbg.NewCborWriter(w)

	// Always encode 3 fields: $type, text, createdAt
	if _, err := cw.Write(cbg.CborEncodeMajorType(cbg.MajMap, uint64(3))); err != nil {
		return err
	}

	// $type field
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len("$type"))); err != nil {
		return err
	}
	if _, err := cw.WriteString("$type"); err != nil {
		return err
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len("com.demo.bskyoauth"))); err != nil {
		return err
	}
	if _, err := cw.WriteString("com.demo.bskyoauth"); err != nil {
		return err
	}

	// text field
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len("text"))); err != nil {
		return err
	}
	if _, err := cw.WriteString("text"); err != nil {
		return err
	}
	if len(t.Text) > 10000 {
		return fmt.Errorf("text field too long (max 10000 characters)")
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(t.Text))); err != nil {
		return err
	}
	if _, err := cw.WriteString(t.Text); err != nil {
		return err
	}

	// createdAt field
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len("createdAt"))); err != nil {
		return err
	}
	if _, err := cw.WriteString("createdAt"); err != nil {
		return err
	}
	if len(t.CreatedAt) > 100 {
		return fmt.Errorf("createdAt field too long")
	}
	if err := cw.WriteMajorTypeHeader(cbg.MajTextString, uint64(len(t.CreatedAt))); err != nil {
		return err
	}
	if _, err := cw.WriteString(t.CreatedAt); err != nil {
		return err
	}

	return nil
}

// UnmarshalCBOR implements cbg.CBORUnmarshaler for DemoRecord
func (t *DemoRecord) UnmarshalCBOR(r io.Reader) (err error) {
	*t = DemoRecord{}

	cr := cbg.NewCborReader(r)

	maj, extra, err := cr.ReadHeader()
	if err != nil {
		return err
	}
	defer func() {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	if maj != cbg.MajMap {
		return fmt.Errorf("expected cbor map (major type 5), got major type %d", maj)
	}

	if extra > cbg.MaxLength {
		return fmt.Errorf("DemoRecord: map struct too large (%d)", extra)
	}

	// Set default type
	t.LexiconTypeID = "com.demo.bskyoauth"

	// Buffer for reading field names
	nameBuf := make([]byte, 16)

	// Read fields
	for i := uint64(0); i < extra; i++ {
		// Read field name
		nameLen, ok, err := cbg.ReadFullStringIntoBuf(cr, nameBuf, 100)
		if err != nil {
			return err
		}

		if !ok {
			// Field doesn't exist on this type, skip it
			if err := cbg.ScanForLinks(cr, func(_ cid.Cid) {}); err != nil {
				return err
			}
			continue
		}

		fieldName := string(nameBuf[:nameLen])

		// Read field value based on field name
		switch fieldName {
		case "$type":
			sval, err := cbg.ReadStringWithMax(cr, 100)
			if err != nil {
				return err
			}
			t.LexiconTypeID = sval

		case "text":
			sval, err := cbg.ReadStringWithMax(cr, 10000)
			if err != nil {
				return err
			}
			t.Text = sval

		case "createdAt":
			sval, err := cbg.ReadStringWithMax(cr, 100)
			if err != nil {
				return err
			}
			t.CreatedAt = sval

		default:
			// Skip unknown fields
			if err := cbg.ScanForLinks(cr, func(_ cid.Cid) {}); err != nil {
				return err
			}
		}
	}

	return nil
}
