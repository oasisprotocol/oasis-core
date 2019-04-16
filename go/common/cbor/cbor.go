// Package cbor provides helpers for encoding and decoding canonical CBOR.
//
// Using this package will produce canonical encodings which can be used
// in cryptographic contexts like signing as the same message is guaranteed
// to always have the same serialization.
package cbor

import "github.com/oasislabs/go-codec/codec"

// Handle is the CBOR codec Handle used to encode/decode CBOR blobs.
var Handle codec.Handle

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
	var b []byte
	enc := codec.NewEncoderBytes(&b, Handle)
	defer enc.Release()
	enc.MustEncode(src)
	return b
}

// Unmarshal deserializes a CBOR byte vector into a given type.
func Unmarshal(data []byte, dst interface{}) error {
	dec := codec.NewDecoderBytes(data, Handle)
	defer dec.Release()
	if err := dec.Decode(dst); err != nil {
		return err
	}

	return nil
}

// MustUnmarshal deserializes a CBOR byte vector into a given type.
// Panics if unmarshal fails.
func MustUnmarshal(data []byte, dst interface{}) {
	if err := Unmarshal(data, dst); err != nil {
		panic(err)
	}
}

func init() {
	h := new(codec.CborHandle)
	h.EncodeOptions.Canonical = true
	h.EncodeOptions.ChanRecvTimeout = -1 // Till chan is closed.
	h.EncodeOptions.ForceNoNatural = true

	Handle = h
}
