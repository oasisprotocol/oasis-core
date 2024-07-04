// Package composite implements support for runtimes composed of multiple components, like having
// both on-chain and off-chain logic.
package composite

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type composite struct {
	id      common.Namespace
	version version.Version
	comps   map[component.ID]host.Runtime

	stopCh chan struct{}

	logger *logging.Logger
}

// Implements host.Runtime.
func (c *composite) ID() common.Namespace {
	return c.id
}

// Implements host.Runtime.
func (c *composite) GetActiveVersion() (*version.Version, error) {
	return c.comps[component.ID_RONL].GetActiveVersion()
}

// Implements host.Runtime.
func (c *composite) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	return c.comps[component.ID_RONL].GetInfo(ctx)
}

// Implements host.Runtime.
func (c *composite) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	return c.comps[component.ID_RONL].GetCapabilityTEE()
}

// shouldPropagateToComponent checks whether the given runtime request should be propagated to the
// given component call.
func shouldPropagateToComponent(body *protocol.Body) bool {
	switch {
	case body.RuntimeConsensusSyncRequest != nil:
		// Consensus view of all components should be up to date as otherwise signed attestations
		// will be stale, resulting in them being rejected.
		return true
	case body.RuntimeKeyManagerStatusUpdateRequest != nil,
		body.RuntimeKeyManagerQuotePolicyUpdateRequest != nil:
		// Key manager updates should be propagated.
		return true
	default:
		return false
	}
}

// Implements host.Runtime.
func (c *composite) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	result, err := c.comps[component.ID_RONL].Call(ctx, body)
	if err != nil {
		return nil, err
	}

	for id, comp := range c.comps {
		if id.IsRONL() {
			continue // Already handled above.
		}
		if !shouldPropagateToComponent(body) {
			continue
		}

		if _, err = comp.Call(ctx, body); err != nil {
			c.logger.Warn("failed to propagate call to component",
				"err", err,
				"component", id,
			)
		}
	}
	return result, nil
}

// Implements host.Runtime.
func (c *composite) UpdateCapabilityTEE() {
	for _, comp := range c.comps {
		comp.UpdateCapabilityTEE()
	}
}

// Implements host.Runtime.
func (c *composite) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	return c.comps[component.ID_RONL].WatchEvents()
}

// Implements host.Runtime.
func (c *composite) Start() {
	for _, comp := range c.comps {
		comp.Start()
	}
}

// Implements host.Runtime.
func (c *composite) Abort(ctx context.Context, force bool) error {
	// Only RONL supports aborts.
	return c.comps[component.ID_RONL].Abort(ctx, force)
}

// Implements host.Runtime.
func (c *composite) Stop() {
	close(c.stopCh)

	for _, comp := range c.comps {
		comp.Stop()
	}
}

// Implements host.CompositeRuntime.
func (c *composite) Component(id component.ID) (host.Runtime, bool) {
	comp, ok := c.comps[id]
	return comp, ok
}

// New creates a new composite runtime host.
func New(cfg host.Config, provisioner host.Provisioner) (host.Runtime, error) {
	// Collect available components.
	availableComps := cfg.Bundle.Manifest.GetAvailableComponents()

	// Collect components that we want.
	wantedComponents := make(map[component.ID]struct{})
	for _, id := range cfg.Components {
		wantedComponents[id] = struct{}{}
	}

	crh := &composite{
		id:      cfg.Bundle.Manifest.ID,
		version: cfg.Bundle.Manifest.Version,
		comps:   make(map[component.ID]host.Runtime),
		stopCh:  make(chan struct{}),
		logger:  logging.GetLogger("runtime/host/composite").With("runtime_id", cfg.Bundle.Manifest.ID),
	}

	// Iterate over all components and provision the individual runtimes.
	for id, c := range availableComps {
		_, wanted := wantedComponents[id]
		if !wanted {
			continue // Skip any components that we don't want.
		}

		compCfg := cfg
		compCfg.Components = []component.ID{id}
		switch id.Kind {
		case component.ROFL:
			// Wrap message handler for ROFL component.
			var err error
			compCfg.MessageHandler, err = compCfg.MessageHandler.NewSubHandler(crh, c)
			if err != nil {
				return nil, fmt.Errorf("host/composite: failed to create sub-handler: %w", err)
			}
		default:
		}

		compRt, err := provisioner.NewRuntime(compCfg)
		if err != nil {
			return nil, fmt.Errorf("host/composite: failed to provision runtime component '%s': %w", id, err)
		}

		crh.comps[id] = compRt
	}
	if _, ronlExists := crh.comps[component.ID_RONL]; !ronlExists {
		return nil, fmt.Errorf("host/composite: required RONL component not available")
	}

	switch {
	case len(crh.comps) == 0:
		// No components are available to be provisioned.
		return nil, fmt.Errorf("host/composite: no components available for provisioning")
	case len(crh.comps) == 1:
		// If there is only a single component, just return the component itself as it doesn't make
		// any sense to have another layer of indirection. This is always the RONL component.
		return crh.comps[component.ID_RONL], nil
	default:
		// Multiple components, create a composite runtime.
		return crh, nil
	}
}
