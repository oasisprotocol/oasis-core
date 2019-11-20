// Package api implements the root hash backend API and common datastructures.
package api

import (
	"context"
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
)

const (
	// BackendName is a unique backend name for the roothash backend.
	BackendName = "roothash"

	// LogEventComputeDiscrepancyDetected is a log event value that signals
	// a compute discrepancy has been detected.
	LogEventComputeDiscrepancyDetected = "roothash/compute_discrepancy_detected"
	// LogEventMergeDiscrepancyDetected is a log event value that signals
	// a compute discrepancy has been detected.
	LogEventMergeDiscrepancyDetected = "roothash/merge_discrepancy_detected"
	// LogEventTimerFired is a log event value that signals a timer has fired.
	LogEventTimerFired = "roothash/timer_fired"
	// LogEventRoundFailed is a log event value that signals a round has failed.
	LogEventRoundFailed = "roothash/round_failed"
	// LogEventMessageUnsat is a log event value that signals a roothash message was not satisfactory.
	LogEventMessageUnsat = "roothash/message_unsat"
)

var (
	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New(BackendName, 1, "roothash: invalid argument")

	// ErrNotFound is the error returned when a block is not found.
	ErrNotFound = errors.New(BackendName, 2, "roothash: block not found")

	// MethodComputeCommit is the method name for compute commit submission.
	MethodComputeCommit = transaction.NewMethodName(BackendName, "ComputeCommit")
	// MethodMergeCommit is the method name for merge commit submission.
	MethodMergeCommit = transaction.NewMethodName(BackendName, "MergeCommit")

	// Methods is a list of all methods supported by the roothash backend.
	Methods = []transaction.MethodName{
		MethodComputeCommit,
		MethodMergeCommit,
	}
)

// Backend is a root hash implementation.
type Backend interface {
	// GetGenesisBlock returns the genesis block.
	GetGenesisBlock(context.Context, signature.PublicKey, int64) (*block.Block, error)

	// GetLatestBlock returns the latest block.
	//
	// The metadata contained in this block can be further used to get
	// the latest state from the storage backend.
	GetLatestBlock(context.Context, signature.PublicKey, int64) (*block.Block, error)

	// GetBlock returns the block at a specific round.
	GetBlock(context.Context, signature.PublicKey, uint64) (*block.Block, error)

	// WatchBlocks returns a channel that produces a stream of
	// annotated blocks.
	//
	// The latest block if any will get pushed to the stream immediately.
	// Subsequent blocks will be pushed into the stream as they are
	// confirmed.
	WatchBlocks(signature.PublicKey) (<-chan *AnnotatedBlock, *pubsub.Subscription, error)

	// WatchEvents returns a stream of protocol events.
	WatchEvents(signature.PublicKey) (<-chan *Event, *pubsub.Subscription, error)

	// WatchPrunedBlocks returns a channel that produces a stream of pruned
	// blocks.
	WatchPrunedBlocks() (<-chan *PrunedBlock, *pubsub.Subscription, error)

	// ToGenesis returns the genesis state at specified block height.
	ToGenesis(context.Context, int64) (*Genesis, error)

	// Cleanup cleans up the roothash backend.
	Cleanup()
}

// ComputeCommit is the argument set for the ComputeCommit method.
type ComputeCommit struct {
	ID      signature.PublicKey            `json:"id"`
	Commits []commitment.ComputeCommitment `json:"commits"`
}

// NewComputeCommitTx creates a new compute commit transaction.
func NewComputeCommitTx(nonce uint64, fee *transaction.Fee, runtimeID signature.PublicKey, commits []commitment.ComputeCommitment) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodComputeCommit, &ComputeCommit{
		ID:      runtimeID,
		Commits: commits,
	})
}

// MergeCommit is the argument set for the MergeCommit method.
type MergeCommit struct {
	ID      signature.PublicKey          `json:"id"`
	Commits []commitment.MergeCommitment `json:"commits"`
}

// NewMergeCommitTx creates a new compute commit transaction.
func NewMergeCommitTx(nonce uint64, fee *transaction.Fee, runtimeID signature.PublicKey, commits []commitment.MergeCommitment) *transaction.Transaction {
	return transaction.NewTransaction(nonce, fee, MethodMergeCommit, &MergeCommit{
		ID:      runtimeID,
		Commits: commits,
	})
}

// AnnotatedBlock is an annotated roothash block.
type AnnotatedBlock struct {
	// Height is the underlying roothash backend's block height that
	// generated this block.
	Height int64

	// Block is the roothash block.
	Block *block.Block
}

// ComputeDiscrepancyDetectedEvent is a compute discrepancy detected event.
type ComputeDiscrepancyDetectedEvent struct {
	// CommitteeID is the identifier of the compute committee where a
	// discrepancy has been detected.
	CommitteeID hash.Hash `json:"cid"`
	// Timeout signals whether the discrepancy was due to a timeout.
	Timeout bool `json:"timeout"`
}

// MergeDiscrepancyDetectedEvent is a merge discrepancy detected event.
type MergeDiscrepancyDetectedEvent struct {
}

// Event is a protocol event.
type Event struct {
	ComputeDiscrepancyDetected *ComputeDiscrepancyDetectedEvent
	MergeDiscrepancyDetected   *MergeDiscrepancyDetectedEvent
}

// MetricsMonitorable is the interface exposed by backends capable of
// providing metrics data.
type MetricsMonitorable interface {
	// WatchAllBlocks returns a channel that produces a stream of blocks.
	//
	// All blocks from all runtimes will be pushed into the stream
	// immediately as they are finalized.
	WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription)
}

// PrunedBlock describes a block that was pruned.
type PrunedBlock struct {
	// RuntimeID is the runtime identifier of the block that was pruned.
	RuntimeID signature.PublicKey
	// Round is the block round.
	Round uint64
}

// Genesis is the roothash genesis state.
type Genesis struct {
	// Blocks is the per-runtime map of genesis blocks.
	Blocks map[signature.PublicKey]*block.Block `json:"blocks,omitempty"`
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	// Check blocks.
	for _, blk := range g.Blocks {
		hdr := blk.Header

		if hdr.HeaderType != block.Normal {
			return fmt.Errorf("roothash: sanity check failed: invalid block header type")
		}

		if !hdr.PreviousHash.IsEmpty() {
			return fmt.Errorf("roothash: sanity check failed: non-empty previous hash")
		}

		if hdr.Timestamp > uint64(time.Now().Unix()+61*60) {
			return fmt.Errorf("roothash: sanity check failed: block header timestamp is more than 1h1m in the future")
		}

		if len(hdr.StorageSignatures) != 0 {
			return fmt.Errorf("roothash: sanity check failed: non-empty storage signatures")
		}

		if len(hdr.RoothashMessages) != 0 {
			return fmt.Errorf("roothash: sanity check failed: non-empty roothash messages")
		}
	}

	return nil
}
