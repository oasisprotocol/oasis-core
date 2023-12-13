// Package composite implements support for runtimes composed of multiple components, like having
// both on-chain and off-chain logic.
package composite

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type composite struct {
	comps map[bundle.ComponentKind]host.Runtime
}

// Implements host.Runtime.
func (c *composite) ID() common.Namespace {
	// All components have the same runtime identifier, so we can just take the RONL one.
	return c.comps[bundle.ComponentRONL].ID()
}

// Implements host.Runtime.
func (c *composite) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	return c.comps[bundle.ComponentRONL].GetInfo(ctx)
}

// Implements host.Runtime.
func (c *composite) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	return c.comps[bundle.ComponentRONL].GetCapabilityTEE()
}

// shouldPropagateToComponent checks whether the given runtime request should be propagated to the
// given component call.
func shouldPropagateToComponent(body *protocol.Body) bool {
	switch {
	case body.RuntimeConsensusSyncRequest != nil:
		// Consensus view of all components should be up to date as otherwise signed attestations
		// will be stale, resulting in them being rejected.
		return true
	case body.RuntimeKeyManagerPolicyUpdateRequest != nil,
		body.RuntimeKeyManagerStatusUpdateRequest != nil,
		body.RuntimeKeyManagerQuotePolicyUpdateRequest != nil:
		// Key manager updates should be propagated.
		return true
	default:
		return false
	}
}

// Implements host.Runtime.
func (c *composite) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	result, err := c.comps[bundle.ComponentRONL].Call(ctx, body)
	if err != nil {
		return nil, err
	}

	for kind, comp := range c.comps {
		if kind == bundle.ComponentRONL {
			continue // Already handled above.
		}
		if !shouldPropagateToComponent(body) {
			continue
		}

		_, err = comp.Call(ctx, body)
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
func (c *composite) WatchEvents(ctx context.Context) (<-chan *host.Event, pubsub.ClosableSubscription, error) {
	return c.comps[bundle.ComponentRONL].WatchEvents(ctx)
}

// Implements host.Runtime.
func (c *composite) Start() error {
	for kind, comp := range c.comps {
		if err := comp.Start(); err != nil {
			return fmt.Errorf("host/composite: failed to start component '%s': %w", kind, err)
		}
	}
	return nil
}

// Implements host.Runtime.
func (c *composite) Abort(ctx context.Context, force bool) error {
	// Only RONL supports aborts.
	return c.comps[bundle.ComponentRONL].Abort(ctx, force)
}

// Implements host.Runtime.
func (c *composite) Stop() {
	for _, comp := range c.comps {
		comp.Stop()
	}
}

// Implements host.CompositeRuntime.
func (c *composite) Component(kind bundle.ComponentKind) host.Runtime {
	return c.comps[kind]
}

// New creates a new composite runtime host.
func New(cfg host.Config, provisioner host.Provisioner) (host.Runtime, error) {
	// Collect available components.
	availableComps := cfg.Bundle.Manifest.GetAvailableComponents()

	// Collect components that we want.
	wantedComponents := make(map[bundle.ComponentKind]struct{})
	for _, kind := range cfg.Components {
		wantedComponents[kind] = struct{}{}
	}

	// Iterate over all components and provision the individual runtimes.
	compRts := make(map[bundle.ComponentKind]host.Runtime)
	for kind, c := range availableComps {
		_, wanted := wantedComponents[kind]
		if !wanted {
			continue // Skip any components that we don't want.
		}

		compCfg := cfg
		compCfg.Components = []bundle.ComponentKind{c.Kind}

		compRt, err := provisioner.NewRuntime(compCfg)
		if err != nil {
			return nil, fmt.Errorf("host/composite: failed to provision runtime component '%s': %w", c.Kind, err)
		}

		compRts[c.Kind] = compRt
	}
	if _, ronlExists := compRts[bundle.ComponentRONL]; !ronlExists {
		return nil, fmt.Errorf("host/composite: required RONL component not available")
	}

	switch {
	case len(compRts) == 0:
		// No components are available to be provisioned.
		return nil, fmt.Errorf("host/composite: no components available for provisioning")
	case len(compRts) == 1:
		// If there is only a single component, just return the component itself as it doesn't make
		// any sense to have another layer of indirection. This is always the RONL component.
		return compRts[bundle.ComponentRONL], nil
	default:
		// Multiple components, create a composite runtime.
		return &composite{
			comps: compRts,
		}, nil
	}
}
