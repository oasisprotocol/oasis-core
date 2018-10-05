package api

import (
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"

	pbRoothash "github.com/oasislabs/ekiden/go/grpc/roothash"
)

var (
	_ cbor.Marshaler   = (*Block)(nil)
	_ cbor.Unmarshaler = (*Block)(nil)
)

// Block is an Oasis block.
type Block struct {
	// Header is the block header.
	Header Header `codec:"header"`

	// ComputationGroup is the designated computation group.
	//
	// Note: This field is omitted from the serialized block.
	ComputationGroup []*scheduler.CommitteeNode `codec:"-"`

	// Commitments is the vector of commitments from compute nodes,
	// in the same order as in the computation group.
	//
	// Note: This field is omitted from the serialized block.
	Commitments []*Commitment `codec:"-"`
}

// Update updates the block header based on the current block content.
func (b *Block) Update() {
	b.Header.GroupHash = b.getComputationGroupHash()
	b.Header.CommitmentsHash = b.getCommitmentsHash()
}

// FromProto deserializes a protobuf into a block.
//
// WARNING: The block is not guaranteed to be internally consistent.
func (b *Block) FromProto(pb *pbRoothash.Block) error {
	if pb == nil {
		return ErrNilProtobuf
	}

	if err := b.Header.FromProto(pb.GetHeader()); err != nil {
		return err
	}

	b.ComputationGroup = nil
	b.Commitments = nil

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

// IsInternallyConsistent returns true iff the block is internally consistent.
//
// A block is considered internally consistent iff the computation group
// AND the commitments vector match the respective hashes in the block
// header.
func (b *Block) IsInternallyConsistent() bool {
	cgroupHash := b.getComputationGroupHash()
	commitsHash := b.getCommitmentsHash()

	return b.Header.GroupHash.Equal(&cgroupHash) && b.Header.CommitmentsHash.Equal(&commitsHash)
}

func (b *Block) getComputationGroupHash() hash.Hash {
	var h hash.Hash

	h.From(b.ComputationGroup)

	return h
}

func (b *Block) getCommitmentsHash() hash.Hash {
	var h hash.Hash

	h.From(b.Commitments)

	return h
}
