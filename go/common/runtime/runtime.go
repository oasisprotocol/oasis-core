package runtime

import (
	"github.com/oasislabs/ekiden/go/common/cbor"
)

var (
	_ cbor.Marshaler   = (*Batch)(nil)
	_ cbor.Unmarshaler = (*Batch)(nil)
)

// Batch is a list of opaque bytes.
type Batch [][]byte

// MarshalCBOR serializes the type into a CBOR byte vector.
func (b Batch) MarshalCBOR() []byte {
	return cbor.Marshal(b)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (b *Batch) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, b)
}
