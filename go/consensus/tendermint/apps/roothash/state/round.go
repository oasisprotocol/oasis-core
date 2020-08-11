package state

import (
	"context"
	"errors"
	"time"

	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

// Round is a roothash round.
type Round struct {
	ExecutorPool *commitment.Pool `json:"executor_pool"`

	CurrentBlock *block.Block `json:"current_block"`
	Finalized    bool         `json:"finalized"`
}

func (r *Round) Reset() {
	r.ExecutorPool.ResetCommitments()
	r.Finalized = false
}

func (r *Round) GetNextTimeout() time.Time {
	return r.ExecutorPool.NextTimeout
}

func (r *Round) AddExecutorCommitment(
	ctx context.Context,
	commitment *commitment.ExecutorCommitment,
	sv commitment.SignatureVerifier,
	nl commitment.NodeLookup,
) error {
	if r.Finalized {
		return errors.New("tendermint/roothash: round is already finalized, can't commit")
	}
	return r.ExecutorPool.AddExecutorCommitment(ctx, r.CurrentBlock, sv, nl, commitment)
}

func (r *Round) Transition(blk *block.Block) {
	r.CurrentBlock = blk
	r.Reset()
}

func NewRound(executorPool *commitment.Pool, blk *block.Block) *Round {
	r := &Round{
		CurrentBlock: blk,
		ExecutorPool: executorPool,
	}
	r.Reset()

	return r
}
