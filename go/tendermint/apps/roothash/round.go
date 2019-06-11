package roothash

import (
	"errors"
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

var (
	_ cbor.Marshaler   = (*round)(nil)
	_ cbor.Unmarshaler = (*round)(nil)
)

type round struct {
	ComputePool *commitment.MultiPool `codec:"compute_pool"`
	MergePool   *commitment.Pool      `codec:"merge_pool"`

	CurrentBlock *block.Block `codec:"current_block"`
	Finalized    bool         `codec:"finalized"`
}

func (r *round) reset() {
	r.ComputePool.ResetCommitments()
	r.MergePool.ResetCommitments()
	r.Finalized = false
}

func (r *round) getNextTimeout() (timeout time.Time) {
	timeout = r.ComputePool.GetNextTimeout()
	if timeout.IsZero() || (!r.MergePool.NextTimeout.IsZero() && r.MergePool.NextTimeout.Before(timeout)) {
		timeout = r.MergePool.NextTimeout
	}
	return
}

func (r *round) addComputeCommitment(commitment *commitment.ComputeCommitment) (*commitment.Pool, error) {
	if r.Finalized {
		return nil, errors.New("tendermint/roothash: round is already finalized, can't commit")
	}
	return r.ComputePool.AddComputeCommitment(r.CurrentBlock, commitment)
}

func (r *round) addMergeCommitment(commitment *commitment.MergeCommitment) error {
	if r.Finalized {
		return errors.New("tendermint/roothash: round is already finalized, can't commit")
	}
	return r.MergePool.AddMergeCommitment(r.CurrentBlock, commitment, r.ComputePool)
}

func (r *round) transition(blk *block.Block) {
	r.CurrentBlock = blk
	r.reset()
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (r *round) MarshalCBOR() []byte {
	return cbor.Marshal(r)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (r *round) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}

func newRound(
	computeCommittee *scheduler.Committee,
	computeNodeInfo map[signature.MapKey]commitment.NodeInfo,
	mergeCommittee *scheduler.Committee,
	mergeNodeInfo map[signature.MapKey]commitment.NodeInfo,
	blk *block.Block,
	runtime *registry.Runtime,
) *round {
	if computeCommittee.Kind != scheduler.Compute {
		panic("roothash/memory: non-compute committee passed to round ctor")
	}
	if mergeCommittee.Kind != scheduler.Merge {
		panic("roothash/memory: non-merge committee passed to round ctor")
	}

	// TODO: Support multiple compute committees (#1775).
	cID := computeCommittee.EncodedMembersHash()
	r := &round{
		CurrentBlock: blk,
		ComputePool: &commitment.MultiPool{
			Committees: map[hash.Hash]*commitment.Pool{
				cID: &commitment.Pool{
					Runtime:   runtime,
					Committee: computeCommittee,
					NodeInfo:  computeNodeInfo,
				},
			},
		},
		MergePool: &commitment.Pool{
			Runtime:   runtime,
			Committee: mergeCommittee,
			NodeInfo:  mergeNodeInfo,
		},
	}
	r.reset()

	return r
}
