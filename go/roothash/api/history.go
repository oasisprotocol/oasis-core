package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// RoundLatest is a special round number always referring to the latest round.
const RoundLatest = RoundInvalid

// BlockHistory is the root hash block history keeper interface.
//
// All methods operate on a specific runtime.
type BlockHistory interface {
	// RuntimeID returns the runtime ID of the runtime this block history is for.
	RuntimeID() common.Namespace

	// Commit commits an annotated block into history.
	//
	// Must be called in order, sorted by round.
	Commit(blk *AnnotatedBlock, roundResults *RoundResults) error

	// LastConsensusHeight returns the last consensus height which was seen
	// by block history.
	LastConsensusHeight() (int64, error)

	// GetCommittedBlock returns the committed block at a specific round.
	// Passing the special value `RoundLatest` will return the latest block.
	//
	// This method can return blocks not yet synced to storage.
	GetCommittedBlock(ctx context.Context, round uint64) (*block.Block, error)

	// ReindexFinished marks an initial history reindex has finished.
	//
	// Calling this methods more then once has no additional side effect.
	ReindexFinished()
}
