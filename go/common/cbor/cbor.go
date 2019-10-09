// Package cbor provides helpers for encoding and decoding canonical CBOR.
//
// Using this package will produce canonical encodings which can be used
// in cryptographic contexts like signing as the same message is guaranteed
// to always have the same serialization.
package cbor

import "github.com/fxamacker/cbor"

// FixSliceForSerde will convert `nil` to `[]byte` to work around serde
// brain damage.
func FixSliceForSerde(b []byte) []byte {
	if b != nil {
		return b
	}
	return []byte{}
}

// Marshaler allows a type to be serialized into CBOR.
type Marshaler interface {
	// MarshalCBOR serializes the type into a CBOR byte vector.
	MarshalCBOR() []byte
}

// Unmarshaler allows a type to be deserialized from CBOR.
type Unmarshaler interface {
	// UnmarshalCBOR deserializes a CBOR byte vector into given type.
	UnmarshalCBOR([]byte) error
}

// Marshal serializes a given type into a CBOR byte vector.
func Marshal(src interface{}) []byte {
	b, err := cbor.Marshal(src, cbor.EncOptions{
		Canonical:   true,
		TimeRFC3339: false, // Second granular unix timestamps
	})
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

	return cbor.Unmarshal(data, dst)
}

// MustUnmarshal deserializes a CBOR byte vector into a given type.
// Panics if unmarshal fails.
func MustUnmarshal(data []byte, dst interface{}) {
	if err := Unmarshal(data, dst); err != nil {
		panic(err)
	}
}
