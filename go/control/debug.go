package control

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/control/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

type debugController struct {
	timeSource beacon.Backend
	registry   registry.Backend
}

func (c *debugController) SetEpoch(ctx context.Context, epoch beacon.EpochTime) error {
	mockTS, ok := c.timeSource.(beacon.SetableBackend)
	if !ok {
		return api.ErrIncompatibleBackend
	}

	return mockTS.SetEpoch(ctx, epoch)
}

func (c *debugController) WaitNodesRegistered(ctx context.Context, count int) error {
	ch, sub, err := c.registry.WatchNodes(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	// Check if there is already enough nodes registered. Note that this request may
	// fail if there is nothing committed yet, so ignore the error.
	nodes, err := c.registry.GetNodes(ctx, 0)
	if err == nil {
		if len(nodes) >= count {
			return nil
		}
	}

	// Wait for more nodes to register.
Loop:
	for {
		select {
		case ev := <-ch:
			if ev.IsRegistration {
				nodes, err = c.registry.GetNodes(ctx, 0)
				if err != nil {
					return err
				}

				if len(nodes) >= count {
					break Loop
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

// New creates a new oasis-node debug controller.
func NewDebug(consensus consensus.Backend) api.DebugController {
	return &debugController{
		timeSource: consensus.Beacon(),
		registry:   consensus.Registry(),
	}
}
