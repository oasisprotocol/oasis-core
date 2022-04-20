package api

import "fmt"

// StatusState is the concise status state of the common runtime worker.
type StatusState uint8

const (
	// StatusStateReady is the ready status state.
	StatusStateReady StatusState = 0
	// StatusStateWaitingRuntime is the waiting for runtime initialization status state.
	StatusStateWaitingRuntime StatusState = 1
	// StatusStateWaitingTrustSync is the waiting for runtime trust sync status state.
	StatusStateWaitingTrustSync StatusState = 2
)

// String returns a string representation of a status state.
func (s StatusState) String() string {
	switch s {
	case StatusStateReady:
		return "ready"
	case StatusStateWaitingRuntime:
		return "waiting for runtime readiness"
	case StatusStateWaitingTrustSync:
		return "waiting for trust sync"
	default:
		return "[invalid status state]"
	}
}

// MarshalText encodes a StatusState into text form.
func (s StatusState) MarshalText() ([]byte, error) {
	switch s {
	case StatusStateReady:
		return []byte(StatusStateReady.String()), nil
	case StatusStateWaitingRuntime:
		return []byte(StatusStateWaitingRuntime.String()), nil
	case StatusStateWaitingTrustSync:
		return []byte(StatusStateWaitingTrustSync.String()), nil
	default:
		return nil, fmt.Errorf("invalid StatusState: %d", s)
	}
}

// UnmarshalText decodes a text slice into a StatusState.
func (s *StatusState) UnmarshalText(text []byte) error {
	switch string(text) {
	case StatusStateReady.String():
		*s = StatusStateReady
	case StatusStateWaitingRuntime.String():
		*s = StatusStateWaitingRuntime
	case StatusStateWaitingTrustSync.String():
		*s = StatusStateWaitingTrustSync
	default:
		return fmt.Errorf("invalid StatusState: %s", string(text))
	}
	return nil
}

// Status is the executor worker status.
type Status struct {
	// Status is a concise status of the committee node.
	Status StatusState `json:"status"`
}
