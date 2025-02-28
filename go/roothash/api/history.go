package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
)

// BlockHistory is the root hash block history keeper interface.
//
// All methods operate on a specific runtime.
type BlockHistory interface {
	// RuntimeID returns the runtime ID of the runtime this block history is for.
	RuntimeID() common.Namespace

	// Commit commits an annotated block with corresponding round results.
	//
	// If notify is set to true, the watchers will be notified about the new block.
	//
	// Any sequence of Commit and CommitBatch calls is valid as long as as blocks
	// are sorted by round.
	//
	// Returns an error if a block at higher or equal round was already committed.
	Commit(blk *AnnotatedBlock, result *RoundResults, notify bool) error

	// CommitBatch commits annotated blocks with corresponding round results.
	//
	// If notify is set to true, the watchers will be notified about all
	// blocks in batch.
	//
	// Within a batch, blocks should be sorted by round. Any sequence of Commit
	// and CommitBatch calls is valid as long as blocks are sorted by round.
	//
	// Returns an error if a block at higher or equal round than the first item
	// in a batch was already committed.
	CommitBatch(blks []*AnnotatedBlock, results []*RoundResults, notify bool) error

	// GetBlock returns committed block at the specific round.
	//
	// Passing the special value `RoundLatest` will return the latest block.
	GetBlock(ctx context.Context, round uint64) (*AnnotatedBlock, error)

	// GetEarliestBlock returns the earliest known committed block.
	GetEarliestBlock(ctx context.Context) (*AnnotatedBlock, error)

	// GetSyncedBlock returns committed and synced block at the specific round.
	//
	// Passing the special value `RoundLatest` will return the latest block.
	GetSyncedBlock(ctx context.Context, round uint64) (*AnnotatedBlock, error)

	// GetEarliestSyncedBlock returns the earliest known committed and synced block.
	GetEarliestSyncedBlock(ctx context.Context) (*AnnotatedBlock, error)

	// GetRoundResults returns the round results for the given round.
	//
	// Passing the special value `RoundLatest` will return results for the latest round.
	GetRoundResults(ctx context.Context, round uint64) (*RoundResults, error)

	// WatchBlocks returns a channel watching blocks as they are committed to storage.
	WatchBlocks() (<-chan *AnnotatedBlock, pubsub.ClosableSubscription, error)

	// WatchSyncedBlocks returns a channel watching blocks as they are committed and synced to storage.
	WatchSyncedBlocks() (<-chan *AnnotatedBlock, pubsub.ClosableSubscription, error)

	// WaitRound waits for the specified round to be committed to storage.
	WaitRound(ctx context.Context, round uint64) (uint64, error)

	// WaitRoundSynced waits for the specified round to be committed and synced to storage.
	WaitRoundSynced(ctx context.Context, round uint64) (uint64, error)

	// LastRound returns the last runtime round which was committed to storage.
	LastRound() (uint64, error)

	// LastSyncedRound returns the last runtime round which was committed and synced to storage.
	LastSyncedRound() (uint64, error)

	// LastConsensusHeight returns the last consensus height which was seen
	// by block history.
	LastConsensusHeight() (int64, error)

	// StorageSyncCheckpoint records the last storage round which was synced
	// to runtime storage.
	StorageSyncCheckpoint(round uint64) error
}
