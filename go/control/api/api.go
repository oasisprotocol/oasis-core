// Package api implements the node control API.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/errors"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

// NodeController is a node controller interface.
type NodeController interface {
	// RequestShutdown requests the node to shut down gracefully.
	//
	// If the wait argument is true then the method will also wait for the
	// shutdown to complete.
	RequestShutdown(ctx context.Context, wait bool) error

	// WaitSync waits for the node to finish syncing.
	// TODO: These should be replaced with WaitReady (see oasis-core#2130).
	WaitSync(ctx context.Context) error

	// IsSynced checks whether the node has finished syncing.
	// TODO: These should be replaced with IsReady (see oasis-core#2130).
	IsSynced(ctx context.Context) (bool, error)
}

// Shutdownable is an interface the node presents for shutting itself down.
type Shutdownable interface {
	// RequestShutdown is the method called by the control server to trigger node shutdown.
	RequestShutdown() <-chan struct{}
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
