// Package block implements the roothash block and header.
package block

import (
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

var (
	_ cbor.Marshaler   = (*Block)(nil)
	_ cbor.Unmarshaler = (*Block)(nil)
)

// Block is an Oasis block.
//
// Keep this in sync with /runtime/src/common/roothash.rs.
type Block struct {
	// Header is the block header.
	Header Header `json:"header"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (b *Block) MarshalCBOR() []byte {
	return cbor.Marshal(b)
}

// UnmarshalCBOR decodes a CBOR marshaled block.
func (b *Block) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, b)
}

// NewGenesisBlock creates a new empty genesis block given a runtime
// id and POSIX timestamp.
func NewGenesisBlock(id signature.PublicKey, timestamp uint64) *Block {
	var blk Block

	blk.Header.Version = 0
	blk.Header.Timestamp = timestamp
	_ = blk.Header.Namespace.UnmarshalBinary(id[:])
	blk.Header.PreviousHash.Empty()
	blk.Header.IORoot.Empty()
	blk.Header.StateRoot.Empty()

	return &blk
}

// NewEmptyBlock creates a new empty block with a specific type.
func NewEmptyBlock(child *Block, timestamp uint64, htype HeaderType) *Block {
	var blk Block

	blk.Header.Version = child.Header.Version
	blk.Header.Namespace = child.Header.Namespace
	blk.Header.Round = child.Header.Round + 1
	blk.Header.Timestamp = timestamp
	blk.Header.HeaderType = htype
	blk.Header.PreviousHash = child.Header.EncodedHash()
	blk.Header.IORoot.Empty()
	// State root is unchanged.
	blk.Header.StateRoot = child.Header.StateRoot

	return &blk
}
