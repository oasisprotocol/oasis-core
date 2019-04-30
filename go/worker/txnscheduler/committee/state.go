package committee

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
		// Batch has been successfully published.
		"WaitingForFinalize",
		// Epoch transition occurred and we are no longer in the committee.
		"NotReady",
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

// StateWaitingForFinalize is the waiting for finalize state.
type StateWaitingForFinalize struct {
}

// String returns a string representation of the state.
func (s StateWaitingForFinalize) String() string {
	return "WaitingForFinalize"
}
