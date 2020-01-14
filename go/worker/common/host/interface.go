package host

import (
	"context"
	"errors"

	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/service"
	"github.com/oasislabs/oasis-core/go/common/version"
	"github.com/oasislabs/oasis-core/go/worker/common/host/protocol"
)

// Host is a worker host.
type Host interface {
	service.BackgroundService

	// MakeRequest sends a request to the worker process.
	MakeRequest(ctx context.Context, body *protocol.Body) (<-chan *protocol.Body, error)

	// Call sends a request to the worker process and returns the response or error.
	Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error)

	// InterruptWorker attempts to interrupt the worker, killing and
	// respawning it if necessary.
	InterruptWorker(ctx context.Context) error

	// WatchEvents returns a channel which produces status change events.
	WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error)
}

// Event is a worker event.
type Event struct {
	Started       *StartedEvent
	FailedToStart *FailedToStartEvent
}

// StartedEvent is a worker started event.
type StartedEvent struct {
	// Version is the runtime version.
	Version version.Version

	// CapabilityTEE is the newly started worker's CapabilityTEE. It may be nil in case the worker
	// is not running inside a TEE.
	CapabilityTEE *node.CapabilityTEE
}

// FailedToStartEvent is a worker failed to start event.
type FailedToStartEvent struct {
	// Error is the error that has occurred.
	Error error
}

// Factory is a factory of worker hosts.
type Factory interface {
	// NewWorkerHost creates a new worker host based on the provided
	// configuration.
	//
	// Some configuration fields may be overriden by the factory.
	NewWorkerHost(cfg Config) (Host, error)
}

// BaseHost provides implementations of common Host methods.
type BaseHost struct {
	Host Host
}

// Call sends a request to the worker process and returns the response or error.
func (h BaseHost) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	respCh, err := h.Host.MakeRequest(ctx, body)
	if err != nil {
		return nil, err
	}

	select {
	case resp, ok := <-respCh:
		if !ok {
			return nil, errors.New("channel closed")
		}

		if resp.Error != nil {
			return nil, errors.New(resp.Error.Message)
		}

		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
