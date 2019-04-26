package host

import (
	"context"

	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/service"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
)

// Host is a worker host.
type Host interface {
	service.BackgroundService

	// MakeRequest sends a request to the worker process.
	MakeRequest(ctx context.Context, body *protocol.Body) (<-chan *protocol.Body, error)

	// WaitForCapabilityTEE gets the active worker's CapabilityTEE,
	// blocking if the active worker is not yet available. The returned
	// CapabilityTEE may be out of date by the time this function returns.
	WaitForCapabilityTEE(ctx context.Context) (*node.CapabilityTEE, error)

	// InterruptWorker attempts to interrupt the worker, killing and
	// respawning it if necessary.
	InterruptWorker(ctx context.Context) error
}
