// Package host implements the functionality to provision and talk to runtimes.
package host

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// Config contains common configuration for the provisioned runtime.
type Config struct {
	// RuntimeID is the unique runtime identifier.
	RuntimeID common.Namespace

	// Path is the path to the resource required for provisioning a runtime. This can be an ELF
	// binary, an SGXS binary or even a VM image. The semantics of this field are entirely up to the
	// used provisioner.
	Path string

	// Extra is an optional provisioner-specific configuration.
	Extra interface{}

	// MessageHandler is the message handler for the Runtime Host Protocol messages.
	MessageHandler protocol.Handler

	// LocalConfig is the node-local runtime configuration.
	LocalConfig map[string]interface{}
}

// Provisioner is the runtime provisioner interface.
type Provisioner interface {
	// NewRuntime provisions a new runtime.
	//
	// This method may return before the runtime is fully provisioned. The returned runtime will not
	// be started automatically, you must call Start explicitly.
	NewRuntime(ctx context.Context, cfg Config) (Runtime, error)
}

// Runtime is a provisioned runtime interface.
type Runtime interface {
	// ID is the runtime identifier.
	ID() common.Namespace

	// GetInfo retrieves the runtime information.
	GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error)

	// Call sends a request message to the runtime over the Runtime Host Protocol and waits for the
	// response (which may be a failure).
	Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error)

	// WatchEvents subscribes to runtime status events.
	WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error)

	// Start attempts to start the runtime.
	Start() error

	// Abort attempts to abort a runtime so that it will be ready to service new requests.
	// In case abort fails or force flag is set, the runtime will be restarted.
	Abort(ctx context.Context, force bool) error

	// Stop signals the provisioned runtime to stop.
	Stop()
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
	// CapabilityTEE is the updated runtime's CapabilityTEE. It may be nil in case the runtime is
	// not running inside a TEE.
	CapabilityTEE *node.CapabilityTEE
}
