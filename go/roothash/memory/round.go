package memory

import (
	"context"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

type round struct {
	ctx context.Context

	computePool *commitment.MultiPool
	mergePool   *commitment.Pool

	currentBlock *block.Block
}

func (r *round) reset() {
	r.computePool.ResetCommitments()
	r.mergePool.ResetCommitments()
}

func (r *round) getNextTimeout() (timeout time.Time) {
	timeout = r.computePool.GetNextTimeout()
	if timeout.IsZero() || (!r.mergePool.NextTimeout.IsZero() && r.mergePool.NextTimeout.Before(timeout)) {
		timeout = r.mergePool.NextTimeout
	}
	return
}

func (r *round) addComputeCommitment(commitment *commitment.ComputeCommitment) (*commitment.Pool, error) {
	return r.computePool.AddComputeCommitment(r.currentBlock, commitment)
}

func (r *round) addMergeCommitment(commitment *commitment.MergeCommitment) error {
	return r.mergePool.AddMergeCommitment(r.currentBlock, commitment, r.computePool)
}

func (r *round) transition(blk *block.Block) {
	r.currentBlock = blk
	r.reset()
}

func newRound(
	ctx context.Context,
	computeCommittee *scheduler.Committee,
	computeNodeInfo map[signature.MapKey]commitment.NodeInfo,
	mergeCommittee *scheduler.Committee,
	mergeNodeInfo map[signature.MapKey]commitment.NodeInfo,
	block *block.Block,
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
		ctx:          ctx,
		currentBlock: block,
		computePool: &commitment.MultiPool{
			Committees: map[hash.Hash]*commitment.Pool{
				cID: &commitment.Pool{
					Runtime:   runtime,
					Committee: computeCommittee,
					NodeInfo:  computeNodeInfo,
				},
			},
		},
		mergePool: &commitment.Pool{
			Runtime:   runtime,
			Committee: mergeCommittee,
			NodeInfo:  mergeNodeInfo,
		},
	}
	r.reset()

	return r
}
