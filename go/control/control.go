// Package control implements an oasis-node controller.
package control

import (
	"context"

	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	control "github.com/oasislabs/oasis-core/go/control/api"
	upgrade "github.com/oasislabs/oasis-core/go/upgrade/api"
)

type nodeController struct {
	node      control.Shutdownable
	consensus consensus.Backend
	upgrader  upgrade.Backend
}

func (c *nodeController) RequestShutdown(ctx context.Context, wait bool) error {
	ch, err := c.node.RequestShutdown()
	if err != nil {
		return err
	}
	if wait {
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (c *nodeController) WaitSync(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.consensus.Synced():
		return nil
	}
}

func (c *nodeController) IsSynced(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-c.consensus.Synced():
		return true, nil
	default:
		return false, nil
	}
}

func (c *nodeController) UpgradeBinary(ctx context.Context, descriptor *upgrade.Descriptor) error {
	return c.upgrader.SubmitDescriptor(ctx, descriptor)
}

func (c *nodeController) CancelUpgrade(ctx context.Context) error {
	return c.upgrader.CancelUpgrade(ctx)
}

// New creates a new oasis-node controller.
func New(node control.Shutdownable, consensus consensus.Backend, upgrader upgrade.Backend) control.NodeController {
	return &nodeController{
		node:      node,
		consensus: consensus,
		upgrader:  upgrader,
	}
}
