package api

import (
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"

	pbRoothash "github.com/oasislabs/ekiden/go/grpc/roothash"
)

// Block is an Oasis block.
type Block struct {
	// Header is the block header.
	Header Header `codec:"header"`

	// ComputationGroup is the designated computation group.
	ComputationGroup []*scheduler.CommitteeNode `codec:"computation_group"`

	// Commitments is the vector of commitments from compute nodes,
	// in the same order as in the computation group.
	Commitments []*Commitment `codec:"commitments"`
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
	for _, v := range pb.GetComputationGroup() {
		node := new(scheduler.CommitteeNode)
		if err := node.FromProto(v); err != nil {
			return err
		}
		b.ComputationGroup = append(b.ComputationGroup, node)
	}

	b.Commitments = nil
	for _, v := range pb.GetCommitments() {
		commit := new(Commitment)
		if err := commit.FromProto(v); err != nil {
			return err
		}
		b.Commitments = append(b.Commitments, commit)
	}

	return nil
}

// ToProto serializes a protobuf into a block.
func (b *Block) ToProto() *pbRoothash.Block {
	resp := new(pbRoothash.Block)
	resp.Header = b.Header.ToProto()
	for _, v := range b.ComputationGroup {
		resp.ComputationGroup = append(resp.ComputationGroup, v.ToProto())
	}
	for _, v := range b.Commitments {
		resp.Commitments = append(resp.Commitments, v.ToProto())
	}

	return resp
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
