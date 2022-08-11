// Package control implements an oasis-node controller.
package control

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	control "github.com/oasisprotocol/oasis-core/go/control/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

type nodeController struct {
	node      control.ControlledNode
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

func (c *nodeController) WaitReady(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.node.Ready():
		return nil
	}
}

func (c *nodeController) IsReady(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-c.node.Ready():
		return true, nil
	default:
		return false, nil
	}
}

func (c *nodeController) UpgradeBinary(ctx context.Context, descriptor *upgrade.Descriptor) error {
	return c.upgrader.SubmitDescriptor(ctx, descriptor)
}

func (c *nodeController) CancelUpgrade(ctx context.Context, descriptor *upgrade.Descriptor) error {
	return c.upgrader.CancelUpgrade(ctx, descriptor)
}

func (c *nodeController) GetStatus(ctx context.Context) (*control.Status, error) {
	cs, err := c.consensus.GetStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get consensus status: %w", err)
	}

	rs, err := c.node.GetRegistrationStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get registration status: %w", err)
	}

	runtimes, err := c.node.GetRuntimeStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get runtime status: %w", err)
	}

	kms, err := c.node.GetKeymanagerStatus(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get key manager worker status: %w", err)
	}

	pendingUpgrades, err := c.node.GetPendingUpgrades(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending upgrades: %w", err)
	}

	ident := c.node.GetIdentity()

	var ds *control.DebugStatus
	if debugEnabled := cmdFlags.DebugDontBlameOasis(); debugEnabled {
		ds = &control.DebugStatus{
			Enabled:   debugEnabled,
			AllowRoot: cmdFlags.DebugAllowRoot(),
		}
	}

	return &control.Status{
		SoftwareVersion: version.SoftwareVersion,
		Debug:           ds,
		Identity: control.IdentityStatus{
			Node:      ident.NodeSigner.Public(),
			P2P:       ident.P2PSigner.Public(),
			Consensus: ident.ConsensusSigner.Public(),
			TLS:       ident.GetTLSPubKeys(),
		},
		Consensus:       *cs,
		Runtimes:        runtimes,
		Keymanager:      kms,
		Registration:    *rs,
		PendingUpgrades: pendingUpgrades,
	}, nil
}

// New creates a new oasis-node controller.
func New(node control.ControlledNode, consensus consensus.Backend, upgrader upgrade.Backend) control.NodeController {
	return &nodeController{
		node:      node,
		consensus: consensus,
		upgrader:  upgrader,
	}
}
