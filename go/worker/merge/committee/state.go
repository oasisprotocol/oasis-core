package committee

import (
	"time"

	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
)

// StateName is a symbolic state without the attached values.
type StateName string

const (
	// NotReady is the name of StateNotReady.
	NotReady = "NotReady"
	// WaitingForResults is the name of StateWaitingForResults.
	WaitingForResults = "WaitingForResults"
	// WaitingForEvent is the name of StateWaitingForEvent.
	WaitingForEvent = "WaitingForEvent"
	// WaitingForFinalize is the name of StateWaitingForFinalize.
	WaitingForFinalize = "WaitingForFinalize"
)

// Valid state transitions.
var validStateTransitions = map[StateName][]StateName{
	// Transitions from NotReady state.
	NotReady: {
		// Epoch transition occurred and we are not in the committee.
		NotReady,
		// Epoch transition occurred and we are in the committee.
		WaitingForResults,
	},

	// Transitions from WaitingForResults state.
	WaitingForResults: {
		// We are waiting for more results.
		WaitingForResults,
		// Received results, waiting for disrepancy event.
		WaitingForEvent,
		// All results have been merged.
		WaitingForFinalize,
		// Epoch transition occurred and we are no longer in the committee.
		NotReady,
	},

	// Transitions from WaitingForEvent state.
	WaitingForEvent: {
		// Abort: seen newer block while waiting for event.
		WaitingForResults,
		// Discrepancy event received.
		WaitingForFinalize,
	},

	// Transitions from WaitingForFinalize state.
	WaitingForFinalize: {
		// Round has been finalized.
		WaitingForResults,
		// Epoch transition occurred and we are no longer in the committee.
		NotReady,
	},
}

// NodeState is a node's state.
type NodeState interface {
	// Name returns the name of the state.
	Name() StateName
}

// StateNotReady is the not ready state.
type StateNotReady struct {
}

// Name returns the name of the state.
func (s StateNotReady) Name() StateName {
	return NotReady
}

// String returns a string representation of the state.
func (s StateNotReady) String() string {
	return string(s.Name())
}

// StateWaitingForResults is the waiting for results state.
type StateWaitingForResults struct {
	pool  *commitment.MultiPool
	timer *time.Timer
}

// Name returns the name of the state.
func (s StateWaitingForResults) Name() StateName {
	return WaitingForResults
}

// String returns a string representation of the state.
func (s StateWaitingForResults) String() string {
	return string(s.Name())
}

// StateWaitingForEvent is the waiting for results state.
type StateWaitingForEvent struct {
	commitments []commitment.ComputeCommitment
	headers     []*block.Header
}

// Name returns the name of the state.
func (s StateWaitingForEvent) Name() StateName {
	return WaitingForEvent
}

// String returns a string representation of the state.
func (s StateWaitingForEvent) String() string {
	return string(s.Name())
}

// StateWaitingForFinalize is the waiting for finalize state.
type StateWaitingForFinalize struct {
}

// Name returns the name of the state.
func (s StateWaitingForFinalize) Name() StateName {
	return WaitingForFinalize
}

// String returns a string representation of the state.
func (s StateWaitingForFinalize) String() string {
	return string(s.Name())
}
