package host

import (
	"context"
	"errors"

	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/common/version"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

// Host is a worker host.
type Host interface {
	service.BackgroundService

	// MakeRequest sends a request to the worker process.
	MakeRequest(ctx context.Context, body *protocol.Body) (<-chan *protocol.Body, error)

	// Call sends a request to the worker process and returns the response or error.
	Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error)

	// WaitForCapabilityTEE gets the active worker's CapabilityTEE,
	// blocking if the active worker is not yet available. The returned
	// CapabilityTEE may be out of date by the time this function returns.
	WaitForCapabilityTEE(ctx context.Context) (*node.CapabilityTEE, error)

	// WaitForRuntimeVersion gets the active worker's version of the Runtime,
	// blocking if the active worker is not yet available. The returned
	// Version may be out of date by the time this function returns.
	WaitForRuntimeVersion(ctx context.Context) (*version.Version, error)

	// InterruptWorker attempts to interrupt the worker, killing and
	// respawning it if necessary.
	InterruptWorker(ctx context.Context) error
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
