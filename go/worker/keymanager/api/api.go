package api

import (
	"fmt"
	"time"

	"github.com/libp2p/go-libp2p/core"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
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

	// ActiveVersion is the currently active version.
	ActiveVersion *version.Version `json:"active_version"`

	// RuntimeID is the runtime ID of the key manager.
	RuntimeID *common.Namespace `json:"runtime_id"`

	// ClientRuntimes is a list of compute runtimes that use this key manager.
	ClientRuntimes []common.Namespace `json:"client_runtimes"`

	// AccessList is per-runtime list of peers that are allowed to call protected methods.
	AccessList []RuntimeAccessList `json:"access_list"`

	// Secrets is the master and ephemeral secrets status.
	Secrets *SecretsStatus `json:"secrets"`
}

// SecretsStatus is the key manager master and ephemeral secrets status.
type SecretsStatus struct {
	// Status is the global key manager committee status.
	Status *api.Status `json:"status"`

	// Worker is the key manager master and ephemeral secrets worker status.
	Worker SecretsWorkerStatus `json:"worker"`
}

// SecretsWorkerStatus is the key manager master and ephemeral secrets worker status.
type SecretsWorkerStatus struct {
	// Status is a concise status of the worker.
	Status StatusState `json:"status"`

	// LastRegistration is the time of the last successful registration with the consensus registry
	// service. In case the worker did not successfully register yet, it will be the zero timestamp.
	LastRegistration time.Time `json:"last_registration"`

	// Policy is the master and ephemeral secrets access control policy.
	Policy *api.SignedPolicySGX `json:"policy"`

	// PolicyChecksum is the checksum of the policy.
	PolicyChecksum []byte `json:"policy_checksum"`

	// MasterSecrets are the master secret generation and replication stats.
	MasterSecrets MasterSecretStats `json:"master_secrets"`

	// EphemeralSecrets are the ephemeral secret generation and replication stats.
	EphemeralSecrets EphemeralSecretStats `json:"ephemeral_secrets"`

	// PrivatePeers is a list of peers that are always allowed to call protected methods.
	PrivatePeers []core.PeerID `json:"private_peers"`
}

// MasterSecretStats are the master secret generation and replication stats.
type MasterSecretStats struct {
	// NumLoaded is the number of loaded secrets.
	NumLoaded int `json:"num_loaded"`

	// LastLoaded is the generation of the last loaded secret.
	LastLoaded uint64 `json:"last_loaded_generation"`

	// NumGenerated is the number of generated secrets.
	NumGenerated int `json:"num_generated"`

	// LastGenerated is the generation of the last generated secret.
	LastGenerated uint64 `json:"last_generated_generation"`
}

// EphemeralSecretStats are the ephemeral secret generation and replication stats.
type EphemeralSecretStats struct {
	// NumLoaded is the number of loaded secrets.
	NumLoaded int `json:"num_loaded"`

	// LastLoaded is the epoch of the last loaded secret.
	LastLoaded beacon.EpochTime `json:"last_loaded_epoch"`

	// NumGenerated is the number of generated secrets.
	NumGenerated int `json:"num_generated"`

	// LastGenerated is the epoch of the last generated secret.
	LastGenerated beacon.EpochTime `json:"last_generated_epoch"`
}

// RPCAccessController handles the authorization of enclave RPC calls.
type RPCAccessController interface {
	// Methods returns a list of allowed methods.
	Methods() []string

	// Connect verifies whether the peer is allowed to establish a secure Noise connection,
	// meaning it is authorized to invoke at least one secure RPC method.
	Connect(peerID core.PeerID) bool

	// Authorize verifies whether the peer is allowed to invoke the specified RPC method.
	Authorize(method string, kind enclaverpc.Kind, peerID core.PeerID) error
}
