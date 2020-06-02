package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// BlockHistory is the root hash block history keeper interface.
//
// All methods operate on a specific runtime.
type BlockHistory interface {
	// RuntimeID returns the runtime ID of the runtime this block history is for.
	RuntimeID() common.Namespace

	// Commit commits an annotated block into history.
	//
	// Must be called in order, sorted by round.
	Commit(blk *AnnotatedBlock) error

	// ConsensusCheckpoint records the last consensus height which was processed
	// by the roothash backend.
	//
	// This method can only be called once all roothash blocks for consensus
	// heights <= height have been committed using Commit.
	ConsensusCheckpoint(height int64) error

	// LastConsensusHeight returns the last consensus height which was seen
	// by block history.
	LastConsensusHeight() (int64, error)

	// GetBlock returns the block at a specific round.
	GetBlock(ctx context.Context, round uint64) (*block.Block, error)

	// GetLatestBlock returns the block at latest round.
	GetLatestBlock(ctx context.Context) (*block.Block, error)
}
