// Package json provides helpers for encoding and decoding canonical JSON.
//
// Using this package will produce canonical encodings which can be used
// in cryptographic contexts like signing as the same message is guaranteed
// to always have the same serialization.
//
// Notes:
//  * The notion of "canonical JSON is somewhat non-standard, and the
//    primary benefit of this package is the ability to use `codec`
//    struct tags uniformly.
//  * Due to the go-codec package's decision tree when encoding/decoding,
//    and signature collisions with the `encoding/json` package, neither
//    a `Marshaler` nor a `Unmarshaler` interface are defined.
package json

import "github.com/oasislabs/go-codec/codec"

// Handle is the JSON codec Handle used to encode/decode JSON blobs.
var Handle codec.Handle

// Marshal serializes a given type into a JSON byte vector.
func Marshal(src interface{}) []byte {
	var b []byte
	enc := codec.NewEncoderBytes(&b, Handle)
	defer enc.Release()
	enc.MustEncode(src)
	return b
}

// Unmarshal deserializes a JSON byte vector into a given type.
func Unmarshal(data []byte, dst interface{}) error {
	// NewDecoderBytes will fail to correctly initialize the decoder
	// if data is nil.
	if data == nil {
		return nil
	}

	dec := codec.NewDecoderBytes(data, Handle)
	defer dec.Release()
	if err := dec.Decode(dst); err != nil {
		return err
	}

	return nil
}

// MustUnmarshal deserializes a JSON byte vector into a given type.
// Panics if unmarshal fails.
func MustUnmarshal(data []byte, dst interface{}) {
	if err := Unmarshal(data, dst); err != nil {
		panic(err)
	}
}

func init() {
	h := new(codec.JsonHandle)
	h.EncodeOptions.Canonical = true

	Handle = h
}
