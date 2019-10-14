package transaction

import "github.com/oasislabs/oasis-core/go/common/cbor"

var (
	_ cbor.Marshaler   = (*RawBatch)(nil)
	_ cbor.Unmarshaler = (*RawBatch)(nil)
)

// RawBatch is a list of opaque bytes.
type RawBatch [][]byte

// String returns a string representation of a batch.
func (b RawBatch) String() string {
	return "<RawBatch>"
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (b RawBatch) MarshalCBOR() []byte {
	return cbor.Marshal(b)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (b *RawBatch) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, b)
}
