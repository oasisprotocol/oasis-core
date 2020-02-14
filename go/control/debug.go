package control

import (
	"context"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"

	"github.com/oasislabs/oasis-core/go/control/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

type debugController struct {
	timeSource epochtime.Backend
	registry   registry.Backend
}

func (c *debugController) SetEpoch(ctx context.Context, epoch epochtime.EpochTime) error {
	mockTS, ok := c.timeSource.(epochtime.SetableBackend)
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
		timeSource: consensus.EpochTime(),
		registry:   consensus.Registry(),
	}
}
