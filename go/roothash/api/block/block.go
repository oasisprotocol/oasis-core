// Package block implements the roothash block and header.
package block

import (
	"errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"

	pbRoothash "github.com/oasislabs/ekiden/go/grpc/roothash"
)

var (
	_ cbor.Marshaler   = (*Block)(nil)
	_ cbor.Unmarshaler = (*Block)(nil)

	errNilProtobuf = errors.New("block: protobuf is nil")
)

// Block is an Oasis block.
type Block struct {
	// Header is the block header.
	Header Header `codec:"header"`
}

// FromProto deserializes a protobuf into a block.
//
// WARNING: The block is not guaranteed to be internally consistent.
func (b *Block) FromProto(pb *pbRoothash.Block) error {
	if pb == nil {
		return errNilProtobuf
	}

	if err := b.Header.FromProto(pb.GetHeader()); err != nil {
		return err
	}

	return nil
}

// ToProto serializes a protobuf into a block.
func (b *Block) ToProto() *pbRoothash.Block {
	resp := new(pbRoothash.Block)
	resp.Header = b.Header.ToProto()

	return resp
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
	blk.Header.InputHash.Empty()
	blk.Header.OutputHash.Empty()
	blk.Header.StateRoot.Empty()

	return &blk
}

// NewEmptyBlock creates a new empty block with a specific type.
func NewEmptyBlock(child *Block, timestamp uint64, htype HeaderType) *Block {
	var blk Block

	blk.Header.Version = child.Header.Version
	blk.Header.Namespace = child.Header.Namespace
	blk.Header.Round = child.Header.Round.Increment()
	blk.Header.Timestamp = timestamp
	blk.Header.HeaderType = htype
	blk.Header.PreviousHash = child.Header.EncodedHash()
	blk.Header.InputHash.Empty()
	blk.Header.OutputHash.Empty()
	// State root is unchanged.
	blk.Header.StateRoot = child.Header.StateRoot
	blk.Header.CommitmentsHash.Empty()

	return &blk
}
