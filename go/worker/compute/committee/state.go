package committee

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

// Valid state transitions.
var validStateTransitions = map[string][]string{
	// Transitions from NotReady state.
	"NotReady": {
		// Epoch transition occurred and we are not in the committee.
		"NotReady",
		// Epoch transition occurred and we are in the committee.
		"WaitingForBatch",
	},

	// Transitions from WaitingForBatch state.
	"WaitingForBatch": {
		"WaitingForBatch",
		// Received batch, need to catch up current block.
		"WaitingForBlock",
		// Received batch, current block is up to date.
		"ProcessingBatch",
		// Epoch transition occurred and we are no longer in the committee.
		"NotReady",
	},

	// Transitions from WaitingForBlock state.
	"WaitingForBlock": {
		// Abort: seen newer block while waiting for block.
		"WaitingForBatch",
		// Seen block that we were waiting for.
		"ProcessingBatch",
	},

	// Transitions from ProcessingBatch state.
	"ProcessingBatch": {
		// Batch has been successfully processed or has been aborted.
		"WaitingForFinalize",
	},

	// Transitions from WaitingForFinalize state.
	"WaitingForFinalize": {
		// Round has been finalized.
		"WaitingForBatch",
		// Epoch transition occurred and we are no longer in the committee.
		"NotReady",
	},
}

// NodeState is a node's state.
type NodeState interface {
	// String returns a string representation of the state.
	String() string
}

// StateNotReady is the not ready state.
type StateNotReady struct {
}

// String returns a string representation of the state.
func (s StateNotReady) String() string {
	return "NotReady"
}

// StateWaitingForBatch is the waiting for batch state.
type StateWaitingForBatch struct {
}

// String returns a string representation of the state.
func (s StateWaitingForBatch) String() string {
	return "WaitingForBatch"
}

// StateWaitingForBlock is the waiting for block state.
type StateWaitingForBlock struct {
	// Batch that is waiting to be processed.
	batch runtime.Batch
	// Header of the block we are waiting for.
	header *block.Header
}

// String returns a string representation of the state.
func (s StateWaitingForBlock) String() string {
	return "WaitingForBlock"
}

// StateProcessingBatch is the processing batch state.
type StateProcessingBatch struct {
	// Batch that is being processed.
	batch runtime.Batch
	// Function for cancelling batch processing.
	cancelFn context.CancelFunc
	// Channel which will provide the result.
	done chan *protocol.ComputedBatch
}

// String returns a string representation of the state.
func (s StateProcessingBatch) String() string {
	return "ProcessingBatch"
}

func (s *StateProcessingBatch) cancel() {
	// Invoke the cancellation function and wait for the processing
	// to actually stop.
	(s.cancelFn)()
	<-s.done
}

// StateWaitingForFinalize is the waiting for finalize state.
type StateWaitingForFinalize struct {
}

// String returns a string representation of the state.
func (s StateWaitingForFinalize) String() string {
	return "WaitingForFinalize"
}
