// Package host implements the functionality to provision and talk to runtimes.
package host

import (
	"context"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// Config contains common configuration for the provisioned runtime.
type Config struct {
	// Bundle is the runtime bundle.
	Bundle *RuntimeBundle

	// Components are optional component ids that should be provisioned in case the runtime has
	// multiple components.
	Components []component.ID

	// Extra is an optional provisioner-specific configuration.
	Extra interface{}

	// MessageHandler is the message handler for the Runtime Host Protocol messages.
	MessageHandler RuntimeHandler

	// LocalConfig is the node-local runtime configuration.
	LocalConfig map[string]interface{}
}

// RuntimeBundle is a exploded runtime bundle ready for execution.
type RuntimeBundle struct {
	*bundle.Bundle

	// ExplodedDataDir is the path to the data directory under which the bundle has been exploded.
	ExplodedDataDir string

	// ExplodedDetachedDirs are the paths to the data directories of detached components.
	ExplodedDetachedDirs map[component.ID]string
}

// ExplodedPath returns the path where the given asset for the given component can be found.
func (bnd *RuntimeBundle) ExplodedPath(comp component.ID, fn string) string {
	if detachedDir, ok := bnd.ExplodedDetachedDirs[comp]; ok {
		return filepath.Join(detachedDir, fn)
	}
	// Default to the exploded bundle.
	return bnd.Bundle.ExplodedPath(bnd.ExplodedDataDir, fn)
}

// Provisioner is the runtime provisioner interface.
type Provisioner interface {
	// NewRuntime provisions a new runtime.
	//
	// This method may return before the runtime is fully provisioned. The returned runtime will not
	// be started automatically, you must call Start explicitly.
	NewRuntime(cfg Config) (Runtime, error)

	// Name returns the name of the provisioner.
	Name() string
}

// Runtime is a provisioned runtime interface.
type Runtime interface {
	// ID is the runtime identifier.
	ID() common.Namespace

	// GetActiveVersion retrieves the version of the currently active runtime.
	GetActiveVersion() (*version.Version, error)

	// GetInfo retrieves the runtime information.
	GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error)

	// GetCapabilityTEE retrieves the CapabilityTEE of the runtime.
	//
	// It may be nil in case the CapabilityTEE is not available or if the runtime is not running
	// inside a TEE.
	GetCapabilityTEE() (*node.CapabilityTEE, error)

	// Call sends a request message to the runtime over the Runtime Host Protocol and waits for the
	// response (which may be a failure).
	Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error)

	// UpdateCapabilityTEE asks the runtime to update its CapabilityTEE with latest data.
	UpdateCapabilityTEE()

	// WatchEvents subscribes to runtime status events.
	WatchEvents() (<-chan *Event, pubsub.ClosableSubscription)

	// Start starts the runtime.
	Start()

	// Abort attempts to abort a runtime so that it will be ready to service new requests.
	// In case abort fails or force flag is set, the runtime will be restarted.
	Abort(ctx context.Context, force bool) error

	// Stop signals the provisioned runtime to stop.
	Stop()
}

// CompositeRuntime is a runtime that provides multiple components which are themselves runtimes.
type CompositeRuntime interface {
	// Component returns the runtime component with the given unique identifier.
	// If the component with the given identifier does not exist, nil is returned.
	Component(id component.ID) (Runtime, bool)
}

// RuntimeHandler is the message handler for the host side of the runtime host protocol.
type RuntimeHandler interface {
	protocol.Handler

	// NewSubHandler creates a sub-handler specialized for the given runtime component.
	NewSubHandler(cr CompositeRuntime, component *bundle.Component) (RuntimeHandler, error)

	// AttachRuntime attaches a given hosted runtime instance to this handler.
	AttachRuntime(host Runtime) error
}

// RuntimeEventEmitter is the interface for emitting events for a provisioned runtime.
type RuntimeEventEmitter interface {
	// EmitEvent allows the caller to emit a runtime event.
	EmitEvent(ev *Event)
}

// Event is a runtime host event.
type Event struct {
	Started       *StartedEvent
	FailedToStart *FailedToStartEvent
	Stopped       *StoppedEvent
	Updated       *UpdatedEvent
	ConfigUpdated *ConfigUpdatedEvent
}

// StartedEvent is a runtime started event.
type StartedEvent struct {
	// Version is the runtime version.
	Version version.Version

	// CapabilityTEE is the newly started runtime's CapabilityTEE. It may be nil in case the runtime
	// is not running inside a TEE.
	CapabilityTEE *node.CapabilityTEE
}

// FailedToStartEvent is a failed to start runtime event.
type FailedToStartEvent struct {
	// Error is the error that has occurred.
	Error error
}

// StoppedEvent is a runtime stopped event.
type StoppedEvent struct{}

// UpdatedEvent is a runtime metadata updated event.
type UpdatedEvent struct {
	// Version is the runtime version.
	Version version.Version

	// CapabilityTEE is the updated runtime's CapabilityTEE. It may be nil in case the runtime is
	// not running inside a TEE.
	CapabilityTEE *node.CapabilityTEE
}

// ConfigUpdatedEvent is a runtime configuration updated event.
//
// This event can be used by runtime host implementations to signal that the underlying runtime
// configuration has changed and some things (e.g. registration) may need a refresh.
type ConfigUpdatedEvent struct{}
