// Package api implements the node control API.
package api

import (
	"context"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

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

	// CancelUpgrade cancels a pending upgrade, unless it is already in progress.
	CancelUpgrade(ctx context.Context) error

	// GetStatus returns the current status overview of the node.
	GetStatus(ctx context.Context) (*Status, error)
}

// Status is the current status overview.
type Status struct {
	// SoftwareVersion is the oasis-node software version.
	SoftwareVersion string `json:"software_version"`

	// Consensus is the status overview of the consensus layer.
	Consensus consensus.Status `json:"consensus"`

	// Registration is the node's registration status.
	Registration RegistrationStatus `json:"registration"`
}

// RegistrationStatus is the node registration status.
type RegistrationStatus struct {
	// LastRegistration is the time of the last successful registration with the consensus registry
	// service. In case the node did not successfully register yet, it will be the zero timestamp.
	LastRegistration time.Time `json:"last_registration"`

	// Descriptor is the node descriptor that the node successfully registered with. In case the
	// node did not successfully register yet, it will be nil.
	Descriptor *node.Node `json:"descriptor,omitempty"`
}

// ControlledNode is an internal interface that the controlled oasis-node must provide.
type ControlledNode interface {
	// RequestShutdown is the method called by the control server to trigger node shutdown.
	RequestShutdown() (<-chan struct{}, error)

	// Ready returns a channel that is closed once node is ready.
	Ready() <-chan struct{}

	// GetRegistrationStatus returns the node's current registration status.
	GetRegistrationStatus(ctx context.Context) (*RegistrationStatus, error)
}

// DebugModuleName is the module name for the debug controller service.
const DebugModuleName = "control/debug"

// ErrIncompatibleBackend is the error raised when the current epochtime
// backend does not support manually setting the current epoch.
var ErrIncompatibleBackend = errors.New(DebugModuleName, 1, "debug: incompatible backend")

// DebugController is a debug-only controller useful during tests.
type DebugController interface {
	// SetEpoch manually sets the current epoch to the given epoch.
	//
	// NOTE: This only works with a mock epochtime backend and will otherwise
	//       return an error.
	SetEpoch(ctx context.Context, epoch epochtime.EpochTime) error

	// WaitNodesRegistered waits for the given number of nodes to register.
	WaitNodesRegistered(ctx context.Context, count int) error
}
