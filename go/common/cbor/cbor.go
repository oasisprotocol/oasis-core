// Package cbor provides helpers for encoding and decoding canonical CBOR.
//
// Using this package will produce canonical encodings which can be used
// in cryptographic contexts like signing as the same message is guaranteed
// to always have the same serialization.
package cbor

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// CfgDebugStrictCBOR enables CBOR round-trip enforcement.
const CfgDebugStrictCBOR = "debug.strict_cbor"

// Flags has the flags used by the CBOR wrapper.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

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

	err := cbor.Unmarshal(data, dst)
	if err != nil {
		return err
	}

	// If we are running with the strict CBOR debug option, ensure that
	// the structure round-trips.
	if viper.GetBool(CfgDebugStrictCBOR) {
		reencoded := Marshal(dst)
		if !bytes.Equal(data, reencoded) {
			msg := fmt.Sprintf(
				"common/cbor: encoded %T does not round-trip (expected: %s, actual: %s)",
				dst,
				hex.EncodeToString(data),
				hex.EncodeToString(reencoded),
			)
			panic(msg)
		}
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

func init() {
	Flags.Bool(CfgDebugStrictCBOR, false, "(DEBUG) Enforce that CBOR blobs roundtrip")
	_ = Flags.MarkHidden(CfgDebugStrictCBOR)

	_ = viper.BindPFlags(Flags)
}
