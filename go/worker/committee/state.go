package committee

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
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

type nodeState interface {
	// String returns a string representation of the state.
	String() string
}

type stateNotReady struct {
}

func (s stateNotReady) String() string {
	return "NotReady"
}

type stateWaitingForBatch struct {
}

func (s stateWaitingForBatch) String() string {
	return "WaitingForBatch"
}

type stateWaitingForBlock struct {
	// Batch that is waiting to be processed.
	batch runtime.Batch
	// Header of the block we are waiting for.
	header *block.Header
}

func (s stateWaitingForBlock) String() string {
	return "WaitingForBlock"
}

type stateProcessingBatch struct {
	// Batch that is being processed.
	batch runtime.Batch
	// Function for cancelling batch processing.
	cancel context.CancelFunc
	// Channel which will provide the result.
	done chan *protocol.ComputedBatch
}

func (s stateProcessingBatch) String() string {
	return "ProcessingBatch"
}

func (s *stateProcessingBatch) Cancel() {
	// Invoke the cancellation function and wait for the processing
	// to actually stop.
	(s.cancel)()
	<-s.done
}

type stateWaitingForFinalize struct {
}

func (s stateWaitingForFinalize) String() string {
	return "WaitingForFinalize"
}
