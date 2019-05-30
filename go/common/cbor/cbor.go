// Package cbor provides helpers for encoding and decoding canonical CBOR.
//
// Using this package will produce canonical encodings which can be used
// in cryptographic contexts like signing as the same message is guaranteed
// to always have the same serialization.
package cbor

import (
	"crypto/sha512"
	"encoding/binary"
	"reflect"

	"github.com/oasislabs/go-codec/codec"
)

// tagBase is a base tag for all Ekiden CBOR extensions.
const tagBase = 0x4515

var typeRegistry map[uint64]bool

type extFwd struct{}

func (e extFwd) ConvertExt(v interface{}) interface{} {
	return v
}

func (e extFwd) UpdateExt(dst interface{}, src interface{}) {
}

func (e extFwd) UseDefault() bool {
	return true
}

// Extension is a type that can be registered as a CBOR extension.
type Extension interface {
}

// RegisterType registers a new CBOR extension.
//
// This function MUST only be called during package init, before the
// CBOR handle is used.
func RegisterType(t Extension, id string) {
	// Derive tag based on given string identifier.
	tagHash := sha512.Sum512_256([]byte(id))
	tag := uint64(tagBase + binary.LittleEndian.Uint32(tagHash[:4]))
	if _, ok := typeRegistry[tag]; ok {
		panic("cbor: duplicate type tag")
	}

	h := Handle.(*codec.CborHandle)
	err := h.SetInterfaceExt(reflect.TypeOf(t), tag, extFwd{})
	if err != nil {
		panic(err)
	}

	if typeRegistry == nil {
		typeRegistry = make(map[uint64]bool)
	}
	typeRegistry[tag] = true
}

// FixSliceForSerde will convert `nil` to `[]byte` to work around serde
// brain damage.
func FixSliceForSerde(b []byte) []byte {
	if b != nil {
		return b
	}
	return []byte{}
}

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
