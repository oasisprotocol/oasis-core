package api

import (
	"fmt"

	"github.com/libp2p/go-libp2p/core"

	"github.com/oasisprotocol/oasis-core/go/common"
)

// StatusState is the concise status state of the key manager worker.
type StatusState uint8

const (
	// StatusStateReady is the ready status state.
	StatusStateReady StatusState = 0
	// StatusStateStarting is the starting status state.
	StatusStateStarting StatusState = 1
	// StatusStateStopped is the stopped status state.
	StatusStateStopped StatusState = 2
	// StatusStateDisabled is the disabled status state.
	StatusStateDisabled StatusState = 3
)

// String returns a string representation of a status state.
func (s StatusState) String() string {
	switch s {
	case StatusStateReady:
		return "ready"
	case StatusStateStarting:
		return "starting"
	case StatusStateStopped:
		return "stopped"
	case StatusStateDisabled:
		return "disabled"
	default:
		return "[invalid status state]"
	}
}

// MarshalText encodes a StatusState into text form.
func (s StatusState) MarshalText() ([]byte, error) {
	switch s {
	case StatusStateReady:
		return []byte(StatusStateReady.String()), nil
	case StatusStateStarting:
		return []byte(StatusStateStarting.String()), nil
	case StatusStateStopped:
		return []byte(StatusStateStopped.String()), nil
	case StatusStateDisabled:
		return []byte(StatusStateDisabled.String()), nil
	default:
		return nil, fmt.Errorf("invalid StatusState: %d", s)
	}
}

// UnmarshalText decodes a text slice into a StatusState.
func (s *StatusState) UnmarshalText(text []byte) error {
	switch string(text) {
	case StatusStateReady.String():
		*s = StatusStateReady
	case StatusStateStarting.String():
		*s = StatusStateStarting
	case StatusStateStopped.String():
		*s = StatusStateStopped
	case StatusStateDisabled.String():
		*s = StatusStateDisabled
	default:
		return fmt.Errorf("invalid StatusState: %s", string(text))
	}
	return nil
}

// RuntimeAccessList is an access control lists for a runtime.
type RuntimeAccessList struct {
	// RuntimeID is the runtime ID of the runtime this access list is for.
	RuntimeID common.Namespace `json:"runtime_id"`

	// Peers is a list of peers that are allowed to call protected methods.
	Peers []core.PeerID `json:"peers"`
}

// Status is the key manager worker status.
type Status struct {
	// Status is a concise status of the key manager worker.
	Status StatusState `json:"status"`

	// MayGenerate returns whether the enclave can generate a master secret.
	MayGenerate bool `json:"may_generate"`

	// RuntimeID is the runtime ID of the key manager.
	RuntimeID *common.Namespace `json:"runtime_id"`
	// ClientRuntimes is a list of compute runtimes that use this key manager.
	ClientRuntimes []common.Namespace `json:"client_runtimes"`

	// AccessList is per-runtime list of peers that are allowed to call protected methods.
	AccessList []RuntimeAccessList `json:"access_list"`
	// PrivatePeers is a list of peers that are always allowed to call protected methods.
	PrivatePeers []core.PeerID `json:"private_peers"`
}
