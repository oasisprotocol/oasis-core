package node

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/beacon/tests"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
)

// Assert that the node implements DebugController interface.
var _ control.DebugController = (*Node)(nil)

// SetEpoch implements control.DebugController.
func (n *Node) SetEpoch(ctx context.Context, epoch beacon.EpochTime) error {
	return tests.SetEpoch(ctx, epoch, n.Consensus)
}

// WaitNodesRegistered implements control.DebugController.
func (n *Node) WaitNodesRegistered(ctx context.Context, count int) error {
	registry := n.Consensus.Registry()

	ch, sub, err := registry.WatchNodes(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	// Check if there is already enough nodes registered. Note that this request may
	// fail if there is nothing committed yet, so ignore the error.
	nodes, err := registry.GetNodes(ctx, 0)
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
				nodes, err = registry.GetNodes(ctx, 0)
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
