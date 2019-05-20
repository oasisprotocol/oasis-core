package committee

// StateName is a symbolic state without the attached values.
type StateName string

const (
	// NotReady is the name of StateNotReady.
	NotReady = "NotReady"
	// WaitingForBatch is the name of StateWaitingForBatch.
	WaitingForBatch = "WaitingForBatch"
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
		WaitingForBatch,
	},

	// Transitions from WaitingForBatch state.
	WaitingForBatch: {
		WaitingForBatch,
		// Batch has been successfully published.
		WaitingForFinalize,
		// Epoch transition occurred and we are no longer in the committee.
		NotReady,
	},

	// Transitions from WaitingForFinalize state.
	WaitingForFinalize: {
		// Round has been finalized.
		WaitingForBatch,
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

// StateWaitingForBatch is the waiting for batch state.
type StateWaitingForBatch struct {
}

// Name returns the name of the state.
func (s StateWaitingForBatch) Name() StateName {
	return WaitingForBatch
}

// String returns a string representation of the state.
func (s StateWaitingForBatch) String() string {
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
