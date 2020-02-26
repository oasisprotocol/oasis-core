// Package cbor provides helpers for encoding and decoding canonical CBOR.
//
// Using this package will produce canonical encodings which can be used
// in cryptographic contexts like signing as the same message is guaranteed
// to always have the same serialization.
package cbor

import (
	"io"

	"github.com/fxamacker/cbor/v2"
)

// RawMessage is a raw encoded CBOR value. It implements Marshaler and
// Unmarshaler interfaces and can be used to delay CBOR decoding or
// precompute a CBOR encoding.
type RawMessage = cbor.RawMessage

var (
	encOptions = cbor.EncOptions{
		Sort:          cbor.SortCanonical,
		ShortestFloat: cbor.ShortestFloat16,
		NaNConvert:    cbor.NaNConvert7e00,
		InfConvert:    cbor.InfConvertFloat16,
		IndefLength:   cbor.IndefLengthForbidden,
		Time:          cbor.TimeUnix,
		TagsMd:        cbor.TagsForbidden,
	}

	decOptions = cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		TagsMd:      cbor.TagsForbidden,
	}

	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	if encMode, err = encOptions.EncMode(); err != nil {
		panic(err)
	}
	if decMode, err = decOptions.DecMode(); err != nil {
		panic(err)
	}
}

// FixSliceForSerde will convert `nil` to `[]byte` to work around serde
// brain damage.
func FixSliceForSerde(b []byte) []byte {
	if b != nil {
		return b
	}
	return []byte{}
}

// Marshal serializes a given type into a CBOR byte vector.
func Marshal(src interface{}) []byte {
	b, err := encMode.Marshal(src)
	if err != nil {
		panic("common/cbor: failed to marshal: " + err.Error())
	}
	return b
}

// Unmarshal deserializes a CBOR byte vector into a given type.
func Unmarshal(data []byte, dst interface{}) error {
	if data == nil {
		return nil
	}

	return decMode.Unmarshal(data, dst)
}

// MustUnmarshal deserializes a CBOR byte vector into a given type.
// Panics if unmarshal fails.
func MustUnmarshal(data []byte, dst interface{}) {
	if err := Unmarshal(data, dst); err != nil {
		panic(err)
	}
}

// NewEncoder creates a new CBOR encoder.
func NewEncoder(w io.Writer) *cbor.Encoder {
	return encMode.NewEncoder(w)
}

// NewDecoder creates a new CBOR decoder.
func NewDecoder(r io.Reader) *cbor.Decoder {
	return decMode.NewDecoder(r)
}
