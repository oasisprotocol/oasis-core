package state

import (
	"errors"
	"time"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
)

// Round is a roothash round.
type Round struct {
	CommitteeID hash.Hash             `json:"committee_id"`
	ComputePool *commitment.MultiPool `json:"compute_pool"`
	MergePool   *commitment.Pool      `json:"merge_pool"`

	CurrentBlock *block.Block `json:"current_block"`
	Finalized    bool         `json:"finalized"`
}

func (r *Round) Reset() {
	r.ComputePool.ResetCommitments()
	r.MergePool.ResetCommitments()
	r.Finalized = false
}

func (r *Round) GetNextTimeout() (timeout time.Time) {
	timeout = r.ComputePool.GetNextTimeout()
	if timeout.IsZero() || (!r.MergePool.NextTimeout.IsZero() && r.MergePool.NextTimeout.Before(timeout)) {
		timeout = r.MergePool.NextTimeout
	}
	return
}

func (r *Round) AddComputeCommitment(commitment *commitment.ComputeCommitment, sv commitment.SignatureVerifier) (*commitment.Pool, error) {
	if r.Finalized {
		return nil, errors.New("tendermint/roothash: round is already finalized, can't commit")
	}
	return r.ComputePool.AddComputeCommitment(r.CurrentBlock, sv, commitment)
}

func (r *Round) AddMergeCommitment(commitment *commitment.MergeCommitment, sv commitment.SignatureVerifier) error {
	if r.Finalized {
		return errors.New("tendermint/roothash: round is already finalized, can't commit")
	}
	return r.MergePool.AddMergeCommitment(r.CurrentBlock, sv, commitment, r.ComputePool)
}

func (r *Round) Transition(blk *block.Block) {
	r.CurrentBlock = blk
	r.Reset()
}

func NewRound(
	committeeID hash.Hash,
	computePool *commitment.MultiPool,
	mergePool *commitment.Pool,
	blk *block.Block,
) *Round {
	r := &Round{
		CommitteeID:  committeeID,
		CurrentBlock: blk,
		ComputePool:  computePool,
		MergePool:    mergePool,
	}
	r.Reset()

	return r
}
