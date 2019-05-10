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

// String returns a string representation of a batch.
func (b Batch) String() string {
	return "<Batch>"
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (b Batch) MarshalCBOR() []byte {
	return cbor.Marshal(b)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (b *Batch) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, b)
}

// TagTxnIndexBlock is the value of a tag's transaction index when the
// tag refers to the block.
const TagTxnIndexBlock int32 = -1

// Tag is a key/value pair of arbitrary byte blobs with runtime-dependent
// semantics which can be indexed to allow easier lookup of blocks and
// transactions on runtime clients.
type Tag struct {
	_struct struct{} `codec:",toarray"` // nolint

	// TxnIndex is a transaction index that this tag belongs to.
	//
	// In case the value is TagTxnIndexBlock, the tag instead refers to
	// the block.
	TxnIndex int32
	// Key is the tag key.
	Key []byte
	// Value is the tag value.
	Value []byte
}

// TxnOutput is an enum that has either Success or Error defined, depending on
// the result of the transaction call.
// It is meant for deserializing CBOR of the corresponding Rust enum defined in
// runtime/src/transaction/types.rs.
type TxnOutput struct {
	// Success can be of any type.
	Success interface{}
	// Error is a string describing the error message.
	Error *string
}
