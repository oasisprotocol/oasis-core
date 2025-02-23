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

	// Commit commits an annotated block into history. If notify is set to true,
	// the watchers will be notified about the new block. Disable notify when
	// doing reindexing.
	//
	// Must be called in order, sorted by round.
	Commit(blk *AnnotatedBlock, roundResults *RoundResults, notify bool) error

	// LastConsensusHeight returns the last consensus height which was seen
	// by block history.
	LastConsensusHeight() (int64, error)

	// GetCommittedBlock returns the committed block at a specific round.
	// Passing the special value `RoundLatest` will return the latest block.
	//
	// This method can return blocks not yet synced to storage.
	GetCommittedBlock(ctx context.Context, round uint64) (*block.Block, error)
}
