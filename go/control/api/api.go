// Package api implements the node control API.
package api

import (
	"context"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	block "github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common/api"
	executorWorker "github.com/oasisprotocol/oasis-core/go/worker/compute/executor/api"
	keymanagerWorker "github.com/oasisprotocol/oasis-core/go/worker/keymanager/api"
	storageWorker "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
)

// ModuleName is the module name for the controller service.
const ModuleName = "control"

// ErrNotImplemented is the error raised when the node does not support the required functionality.
var ErrNotImplemented = errors.New(ModuleName, 1, "control: not implemented")

// NodeController is a node controller interface.
type NodeController interface {
	// RequestShutdown requests the node to shut down gracefully.
	//
	// If the wait argument is true then the method will also wait for the
	// shutdown to complete.
	RequestShutdown(ctx context.Context, wait bool) error

	// WaitSync waits for the node to finish syncing.
	WaitSync(ctx context.Context) error

	// IsSynced checks whether the node has finished syncing.
	IsSynced(ctx context.Context) (bool, error)

	// WaitReady waits for the node to accept runtime work.
	WaitReady(ctx context.Context) error

	// IsReady checks whether the node is ready to accept runtime work.
	IsReady(ctx context.Context) (bool, error)

	// UpgradeBinary submits an upgrade descriptor to a running node.
	// The node will wait for the appropriate epoch, then update its binaries
	// and shut down.
	UpgradeBinary(ctx context.Context, descriptor *upgrade.Descriptor) error

	// CancelUpgrade cancels the specific pending upgrade, unless it is already in progress.
	CancelUpgrade(ctx context.Context, descriptor *upgrade.Descriptor) error

	// GetStatus returns the current status overview of the node.
	GetStatus(ctx context.Context) (*Status, error)

	// AddBundle adds bundle from the given path.
	//
	// If the bundle upgrades an existing ROFL component, the latter will
	// be upgraded to the new version.
	AddBundle(ctx context.Context, path string) error
}

// Status is the current status overview.
type Status struct {
	// SoftwareVersion is the oasis-node software version.
	SoftwareVersion string `json:"software_version"`

	// Mode is the node mode.
	Mode config.NodeMode `json:"mode"`

	// Debug is the oasis-node debug status.
	Debug *DebugStatus `json:"debug,omitempty"`

	// Identity is the identity of the node.
	Identity IdentityStatus `json:"identity"`

	// Consensus is the status overview of the consensus layer.
	Consensus *consensus.Status `json:"consensus,omitempty"`

	// LightClient is the status overview of the light client service.
	LightClient *consensus.LightClientStatus `json:"light_client,omitempty"`

	// Runtimes is the status overview for each runtime supported by the node.
	Runtimes map[common.Namespace]RuntimeStatus `json:"runtimes,omitempty"`

	// Registration is the node's registration status.
	Registration *RegistrationStatus `json:"registration,omitempty"`

	// Keymanager is the node's key manager worker status if the node is a key manager node.
	Keymanager *keymanagerWorker.Status `json:"keymanager,omitempty"`

	// PendingUpgrades are the node's pending upgrades.
	PendingUpgrades []*upgrade.PendingUpgrade `json:"pending_upgrades,omitempty"`

	// P2P is the P2P status of the node.
	P2P *p2p.Status `json:"p2p,omitempty"`

	// Seed is the seed node status if the node is a seed node.
	Seed *SeedStatus `json:"seed,omitempty"`
}

// DebugStatus is the current node debug status, listing the various node
// debug options if enabled.
type DebugStatus struct {
	// Enabled is true iff the node is running with DebugDontBlameOasis
	// set.
	Enabled bool `json:"enabled"`

	// AllowRoot is true iff the node is running with DebugAllowRoot
	// set.
	AllowRoot bool `json:"allow_root"`
}

// IdentityStatus is the current node identity status, listing all the public keys that identify
// this node in different contexts.
type IdentityStatus struct {
	// Node is the node identity public key.
	Node signature.PublicKey `json:"node"`

	// Consensus is the consensus public key.
	Consensus signature.PublicKey `json:"consensus"`

	// TLS is the public key used for TLS connections.
	TLS signature.PublicKey `json:"tls"`
}

// RegistrationStatus is the node registration status.
type RegistrationStatus struct {
	// LastAttemptSuccessful is true if the last registration attempt has been
	// successful.
	LastAttemptSuccessful bool `json:"last_attempt_successful"`

	// LastAttemptErrorMessage contains the error message if the last
	// registration attempt has not been successful.
	LastAttemptErrorMessage string `json:"last_attempt_error_message,omitempty"`

	// LastAttempt is the time of the last registration attempt.
	// In case the node did not successfully register yet, it will be the zero timestamp.
	LastAttempt time.Time `json:"last_attempt"`

	// LastRegistration is the time of the last successful registration with the consensus registry
	// service. In case the node did not successfully register yet, it will be the zero timestamp.
	LastRegistration time.Time `json:"last_registration"`

	// Descriptor is the node descriptor that the node successfully registered with. In case the
	// node did not successfully register yet, it will be nil.
	Descriptor *node.Node `json:"descriptor,omitempty"`

	// NodeStatus is the registry live status of the node.
	NodeStatus *registry.NodeStatus `json:"node_status,omitempty"`
}

// RuntimeStatus is the per-runtime status overview.
type RuntimeStatus struct {
	// Descriptor is the runtime registration descriptor.
	Descriptor *registry.Runtime `json:"descriptor"`

	// LatestRound is the round of the latest runtime block.
	LatestRound uint64 `json:"latest_round"`
	// LatestHash is the hash of the latest runtime block.
	LatestHash hash.Hash `json:"latest_hash"`
	// LatestTime is the timestamp of the latest runtime block.
	LatestTime block.Timestamp `json:"latest_time"`
	// LatestStateRoot is the Merkle root of the runtime state tree.
	LatestStateRoot storage.Root `json:"latest_state_root"`

	// GenesisRound is the round of the genesis runtime block.
	GenesisRound uint64 `json:"genesis_round"`
	// GenesisHash is the hash of the genesis runtime block.
	GenesisHash hash.Hash `json:"genesis_hash"`

	// LastRetainedRound is the round of the oldest retained block.
	LastRetainedRound uint64 `json:"last_retained_round"`
	// LastRetainedHash is the hash of the oldest retained block.
	LastRetainedHash hash.Hash `json:"last_retained_hash"`

	// Committee contains the runtime common committee worker status.
	Committee *commonWorker.Status `json:"committee"`
	// Executor contains the executor worker status in case this node is an executor node.
	Executor *executorWorker.Status `json:"executor,omitempty"`
	// Storage contains the storage worker status in case this node is a storage node.
	Storage *storageWorker.Status `json:"storage,omitempty"`
	// Indexer contains the runtime history indexer status in case this runtime has a block indexer.
	Indexer *history.IndexerStatus `json:"indexer,omitempty"`

	// Provisioner is the name of the runtime provisioner.
	Provisioner string `json:"provisioner,omitempty"`

	// Components contains statuses of the runtime components.
	Components []ComponentStatus `json:"components,omitempty"`
}

// ComponentStatus is the runtime component status overview.
type ComponentStatus struct {
	// Kind is the component kind.
	Kind component.Kind `json:"kind"`

	// Name is the name of the component.
	Name string `json:"name,omitempty"`

	// Version is the component version.
	Version version.Version `json:"version,omitempty"`

	// Detached specifies whether the component was in a detached bundle.
	Detached bool `json:"detached,omitempty"`

	// Disabled specifies whether the component is disabled by default
	// and needs to be explicitly enabled via node configuration to be used.
	Disabled bool `json:"disabled,omitempty"`
}

// SeedStatus is the status of the seed node.
type SeedStatus struct {
	// ChainContext is the chain domain separation context.
	ChainContext string `json:"chain_context"`

	// Addresses is a list of seed node's addresses.
	Addresses []string `json:"addresses"`

	// NodePeers is a list of peers that are connected to the node.
	NodePeers []string `json:"node_peers"`
}

// DebugModuleName is the module name for the debug controller service.
const DebugModuleName = "control/debug"

// DebugController is a debug-only controller useful during tests.
type DebugController interface {
	// SetEpoch manually sets the current epoch to the given epoch.
	//
	// NOTE: This only works with a mock beacon backend and will otherwise
	//       return an error.
	SetEpoch(ctx context.Context, epoch beacon.EpochTime) error

	// WaitNodesRegistered waits for the given number of nodes to register.
	WaitNodesRegistered(ctx context.Context, count int) error
}
