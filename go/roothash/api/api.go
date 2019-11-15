// Package api implements the root hash backend API and common datastructures.
package api

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
)

const (
	// HashSize is the size of the various hashes in bytes.
	HashSize = 32

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
	// ErrMalformedHash is the error returned when a hash is malformed.
	ErrMalformedHash = errors.New("roothash: malformed hash")

	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New("roothash: invalid argument")

	// ErrNotFound is the error returned when a block is not found.
	ErrNotFound = errors.New("roothash: block not found")

	_ cbor.Marshaler   = (*ComputeDiscrepancyDetectedEvent)(nil)
	_ cbor.Unmarshaler = (*ComputeDiscrepancyDetectedEvent)(nil)
	_ cbor.Marshaler   = (*MergeDiscrepancyDetectedEvent)(nil)
	_ cbor.Unmarshaler = (*MergeDiscrepancyDetectedEvent)(nil)
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

	// MergeCommit submits a batch of merge commitments.
	MergeCommit(context.Context, signature.PublicKey, []commitment.MergeCommitment) error

	// ComputeCommit submits a batch of compute commitments for slashing.
	ComputeCommit(context.Context, signature.PublicKey, []commitment.ComputeCommitment) error

	// ConsensusParameters returns consensus parameters at specified block height.
	ConsensusParameters(context.Context, int64) (*ConsensusParameters, error)

	// ToGenesis returns the genesis state at specified block height.
	ToGenesis(context.Context, int64) (*Genesis, error)

	// Cleanup cleans up the roothash backend.
	Cleanup()
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

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e *ComputeDiscrepancyDetectedEvent) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR decodes a CBOR marshaled event.
func (e *ComputeDiscrepancyDetectedEvent) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
}

// MergeDiscrepancyDetectedEvent is a merge discrepancy detected event.
type MergeDiscrepancyDetectedEvent struct {
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e *MergeDiscrepancyDetectedEvent) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR decodes a CBOR marshaled event.
func (e *MergeDiscrepancyDetectedEvent) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
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
	// Parameters are the roothash consensus parameters.
	Parameters ConsensusParameters `json:"params"`

	// Blocks is the per-runtime map of genesis blocks.
	Blocks map[signature.PublicKey]*block.Block `json:"blocks,omitempty"`
}

// ConsensusParameters are the roothash consensus parameters.
type ConsensusParameters struct {
	// RoundTimeout is the round timeout.
	RoundTimeout time.Duration `json:"round_timeout"`

	// TransactionScheduler is the transaction scheduler configuration.
	TransactionScheduler TransactionSchedulerParameters `json:"txn_scheduler"`
}

// TransactionSchedulerAlgorithmBatching is the name of the batching algorithm.
const TransactionSchedulerAlgorithmBatching = "batching"

// TransactionSchedulerParameters is the transaction scheduler parameters.
type TransactionSchedulerParameters struct {
	// Algorithm is the transaction scheduling algorithm.
	Algorithm string `json:"algorithm"`

	// If using the "batching" algoritm, how long to wait for a scheduled batch.
	BatchFlushTimeout time.Duration `json:"batch_flush_timeout"`

	// If using the "batching" algorithm, what is the max size of a batch.
	MaxBatchSize uint64 `json:"max_batch_size"`

	// If using the "batching" algorithm, what is the max size of a batch
	// in bytes.
	MaxBatchSizeBytes uint64 `json:"max_batch_size_bytes"`
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	if g.Parameters.RoundTimeout < 1*time.Second {
		return fmt.Errorf("roothash: sanity check failed: round timeout must be >= 1 second")
	}

	if g.Parameters.TransactionScheduler.Algorithm != TransactionSchedulerAlgorithmBatching {
		return fmt.Errorf("roothash: sanity check failed: invalid txn sched algorithm")
	}

	if g.Parameters.TransactionScheduler.BatchFlushTimeout < 1*time.Second {
		return fmt.Errorf("roothash: sanity check failed: batch flush timeout must be >= 1 second")
	}

	if g.Parameters.TransactionScheduler.MaxBatchSize < 1 {
		return fmt.Errorf("roothash: sanity check failed: max batch size must be >= 1")
	}

	if g.Parameters.TransactionScheduler.MaxBatchSizeBytes < 1 {
		return fmt.Errorf("roothash: sanity check failed: max batch size in bytes must be >= 1")
	}

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
