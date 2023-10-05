package committee

import (
	"context"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

// StateName is a symbolic state without the attached values.
type StateName string

const (
	// WaitingForBatch is the name of StateWaitingForBatch.
	WaitingForBatch = "WaitingForBatch"
	// WaitingForTxs is the name of the StateWaitingForTxs.
	WaitingForTxs = "WaitingForTxs"
	// WaitingForEvent is the name of StateWaitingForEvent.
	WaitingForEvent = "WaitingForEvent"
	// ProcessingBatch is the name of StateProcessingBatch.
	ProcessingBatch = "ProcessingBatch"
)

// Valid state transitions.
var validStateTransitions = map[StateName][]StateName{
	// Transitions from WaitingForBatch state.
	WaitingForBatch: {
		// Waiting batch, e.g. round ended.
		WaitingForBatch,
		// Received batch, current block is up to date.
		ProcessingBatch,
		// Received batch, waiting for discrepancy event.
		WaitingForEvent,
		// Received batch, waiting for missing transactions.
		WaitingForTxs,
	},

	WaitingForTxs: {
		// Received batch with better rank or round ended.
		WaitingForBatch,
		// Received all missing transactions, waiting for discrepancy event.
		WaitingForEvent,
		// Received all missing transactions (and discrepancy event).
		ProcessingBatch,
	},

	// Transitions from WaitingForEvent state.
	WaitingForEvent: {
		// Received batch with better rank or round ended.
		WaitingForBatch,
		// Received discrepancy event.
		ProcessingBatch,
	},

	// Transitions from ProcessingBatch state.
	ProcessingBatch: {
		// Received batch with better rank or round ended.
		WaitingForBatch,
	},
}

// NodeState is a node's state.
type NodeState interface {
	// Name returns the name of the state.
	Name() StateName
}

// StateWaitingForBatch is the waiting for batch state.
type StateWaitingForBatch struct{}

// Name returns the name of the state.
func (s StateWaitingForBatch) Name() StateName {
	return WaitingForBatch
}

// String returns a string representation of the state.
func (s StateWaitingForBatch) String() string {
	return string(s.Name())
}

// StateWaitingForEvent is the waiting for event state.
type StateWaitingForEvent struct {
	proposal *commitment.Proposal
	rank     uint64

	batch transaction.RawBatch
}

// Name returns the name of the state.
func (s StateWaitingForEvent) Name() StateName {
	return WaitingForEvent
}

// String returns a string representation of the state.
func (s StateWaitingForEvent) String() string {
	return string(s.Name())
}

type StateWaitingForTxs struct {
	proposal *commitment.Proposal
	rank     uint64

	batch transaction.RawBatch
	txs   map[hash.Hash]int

	bytes        uint64
	maxBytes     uint64
	batchSize    uint64
	maxBatchSize uint64

	cancelFn context.CancelFunc
	done     chan struct{}
}

// Name returns the name of the state.
func (s StateWaitingForTxs) Name() StateName {
	return WaitingForTxs
}

// String returns a string representation of the state.
func (s StateWaitingForTxs) String() string {
	return string(s.Name())
}

// Cancel invokes the cancellation function and waits for the fetching to actually stop.
func (s StateWaitingForTxs) Cancel() {
	s.cancelFn()
	<-s.done
}

// StateProcessingBatch is the processing batch state.
type StateProcessingBatch struct {
	rank uint64

	// Execution mode.
	mode protocol.ExecutionMode
	// Timing for this batch.
	batchStartTime time.Time
	// Function for cancelling batch processing.
	cancelFn context.CancelFunc
	// Channel which will provide the result.
	done chan struct{}
}

// Name returns the name of the state.
func (s StateProcessingBatch) Name() StateName {
	return ProcessingBatch
}

// String returns a string representation of the state.
func (s StateProcessingBatch) String() string {
	return string(s.Name())
}

// Cancel invokes the cancellation function and waits for the processing to actually stop.
func (s *StateProcessingBatch) Cancel() {
	s.cancelFn()
	<-s.done
}

type processedBatch struct {
	proposal *commitment.Proposal
	rank     uint64

	computed *protocol.ComputedBatch
	raw      transaction.RawBatch

	txInputWriteLog storage.WriteLog
}

type proposedBatch struct {
	batchStartTime time.Time
	proposedIORoot hash.Hash
	txHashes       []hash.Hash
}
