package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// BlockHistory is the root hash block history keeper interface.
//
// All methods operate on a specific runtime.
type BlockHistory interface {
	// RuntimeID returns the runtime ID of the runtime this block history is for.
	RuntimeID() common.Namespace

	// Commit commits an annotated block.
	//
	// If notify is set to true, the watchers will be notified about the new block.
	//
	// Any sequence of Commit and CommitBatch calls is valid as long as as blocks
	// are sorted by round.
	//
	// Returns an error if a block at higher or equal round was already committed.
	Commit(blk *AnnotatedBlock, notify bool) error

	// CommitBatch commits annotated blocks.
	//
	// If notify is set to true, the watchers will be notified about all
	// blocks in batch.
	//
	// Within a batch, blocks should be sorted by round. Any sequence of Commit
	// and CommitBatch calls is valid as long as blocks are sorted by round.
	//
	// Returns an error if a block at higher or equal round than the first item
	// in a batch was already committed.
	CommitBatch(blks []*AnnotatedBlock, notify bool) error

	// StorageSyncCheckpoint records the last storage round which was synced
	// to runtime storage.
	StorageSyncCheckpoint(round uint64) error

	// LastStorageSyncedRound returns the last runtime round which was synced to storage.
	LastStorageSyncedRound() (uint64, error)

	// WatchBlocks returns a channel watching block rounds as they are committed.
	// If node has local storage this includes waiting for the round to be synced into storage.
	WatchBlocks() (<-chan *AnnotatedBlock, pubsub.ClosableSubscription, error)

	// WatchCommittedBlocks returns a channel watching block rounds as they are committed.
	WatchCommittedBlocks() (<-chan *AnnotatedBlock, pubsub.ClosableSubscription, error)

	// WaitRoundSynced waits for the specified round to be synced to storage.
	WaitRoundSynced(ctx context.Context, round uint64) (uint64, error)

	// LastConsensusHeight returns the last consensus height which was seen
	// by block history.
	LastConsensusHeight() (int64, error)

	// GetCommittedBlock returns the committed block at a specific round.
	// Passing the special value `RoundLatest` will return the latest block.
	//
	// This method can return blocks not yet synced to storage.
	GetCommittedBlock(ctx context.Context, round uint64) (*block.Block, error)

	// GetBlock returns the block at a specific round.
	// Passing the special value `RoundLatest` will return the latest block.
	//
	// This method returns blocks that are both committed and synced to storage.
	GetBlock(ctx context.Context, round uint64) (*block.Block, error)

	// GetAnnotatedBlock returns the annotated block at a specific round.
	//
	// Passing the special value `RoundLatest` will return the latest annotated block.
	GetAnnotatedBlock(ctx context.Context, round uint64) (*AnnotatedBlock, error)

	// GetEarliestBlock returns the earliest known block.
	GetEarliestBlock(ctx context.Context) (*block.Block, error)
}
