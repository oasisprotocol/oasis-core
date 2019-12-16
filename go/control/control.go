// Package control implements an oasis-node controller.
package control

import (
	"context"

	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/control/api"
)

type nodeController struct {
	node      api.Shutdownable
	consensus consensus.Backend
}

func (c *nodeController) RequestShutdown(ctx context.Context, wait bool) error {
	ch := c.node.RequestShutdown()
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

// New creates a new oasis-node controller.
func New(node api.Shutdownable, consensus consensus.Backend) api.NodeController {
	return &nodeController{
		node:      node,
		consensus: consensus,
	}
}
