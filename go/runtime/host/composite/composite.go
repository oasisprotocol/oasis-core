// Package composite implements support for runtimes composed of multiple components, like having
// both on-chain and off-chain logic.
package composite

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type rhost struct {
	id      common.Namespace
	version version.Version
	comps   map[component.ID]host.Runtime

	stopCh chan struct{}

	logger *logging.Logger
}

// NewHost creates a new composite runtime host.
func NewHost(cfg host.Config, provisioner host.Provisioner) (host.Runtime, error) {
	h := &rhost{
		id:     cfg.Bundle.Manifest.ID,
		comps:  make(map[component.ID]host.Runtime),
		stopCh: make(chan struct{}),
		logger: logging.GetLogger("runtime/host/composite").With("runtime_id", cfg.Bundle.Manifest.ID),
	}

	// Collect available components.
	availableComps := cfg.Bundle.Manifest.GetAvailableComponents()

	// Iterate over all wanted components and provision the individual runtimes.
	for _, id := range cfg.Components {
		c, ok := availableComps[id]
		if !ok {
			continue // Skip any components that we want but don't have.
		}

		compCfg := cfg
		compCfg.Components = []component.ID{id}
		switch id.Kind {
		case component.RONL:
			h.version = c.Version
		case component.ROFL:
			// Wrap message handler for ROFL component.
			var err error
			compCfg.MessageHandler, err = compCfg.MessageHandler.NewSubHandler(h, c)
			if err != nil {
				return nil, fmt.Errorf("host/composite: failed to create sub-handler: %w", err)
			}
		default:
		}

		compRt, err := provisioner.NewRuntime(compCfg)
		if err != nil {
			return nil, fmt.Errorf("host/composite: failed to provision runtime component '%s': %w", id, err)
		}

		h.comps[id] = compRt
	}
	if _, ronlExists := h.comps[component.ID_RONL]; !ronlExists {
		return nil, fmt.Errorf("host/composite: required RONL component not available")
	}

	switch {
	case len(h.comps) == 0:
		// No components are available to be provisioned.
		return nil, fmt.Errorf("host/composite: no components available for provisioning")
	case len(h.comps) == 1:
		// If there is only a single component, just return the component itself as it doesn't make
		// any sense to have another layer of indirection. This is always the RONL component.
		return h.comps[component.ID_RONL], nil
	default:
		// Multiple components, create a composite runtime.
		return h, nil
	}
}

// Implements host.Runtime.
func (h *rhost) ID() common.Namespace {
	return h.id
}

// Implements host.Runtime.
func (h *rhost) GetActiveVersion() (*version.Version, error) {
	return h.comps[component.ID_RONL].GetActiveVersion()
}

// Implements host.Runtime.
func (h *rhost) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	return h.comps[component.ID_RONL].GetInfo(ctx)
}

// Implements host.Runtime.
func (h *rhost) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	return h.comps[component.ID_RONL].GetCapabilityTEE()
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
func (h *rhost) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	result, err := h.comps[component.ID_RONL].Call(ctx, body)
	if err != nil {
		return nil, err
	}

	for id, comp := range h.comps {
		if id.IsRONL() {
			continue // Already handled above.
		}
		if !shouldPropagateToComponent(body) {
			continue
		}

		if _, err = comp.Call(ctx, body); err != nil {
			h.logger.Warn("failed to propagate call to component",
				"err", err,
				"component", id,
			)
		}
	}
	return result, nil
}

// Implements host.Runtime.
func (h *rhost) UpdateCapabilityTEE() {
	for _, comp := range h.comps {
		comp.UpdateCapabilityTEE()
	}
}

// Implements host.Runtime.
func (h *rhost) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	return h.comps[component.ID_RONL].WatchEvents()
}

// Implements host.Runtime.
func (h *rhost) Start() {
	for _, comp := range h.comps {
		comp.Start()
	}
}

// Implements host.Runtime.
func (h *rhost) Abort(ctx context.Context, force bool) error {
	// Only RONL supports aborts.
	return h.comps[component.ID_RONL].Abort(ctx, force)
}

// Implements host.Runtime.
func (h *rhost) Stop() {
	close(h.stopCh)

	for _, comp := range h.comps {
		comp.Stop()
	}
}

// Implements host.CompositeRuntime.
func (h *rhost) Component(id component.ID) (host.Runtime, bool) {
	comp, ok := h.comps[id]
	return comp, ok
}

type provisioner struct {
	kinds map[component.TEEKind]host.Provisioner
}

// NewProvisioner returns a composite provisioner that dispatches to the actual provisioner based
// on the component kind.
func NewProvisioner(kinds map[component.TEEKind]host.Provisioner) host.Provisioner {
	return &provisioner{kinds: kinds}
}

// Implements host.Provisioner.
func (p *provisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	if len(cfg.Components) != 1 {
		return nil, fmt.Errorf("host/composite: exactly one component should be selected")
	}

	comp := cfg.Bundle.Manifest.GetComponentByID(cfg.Components[0])
	if comp == nil {
		return nil, fmt.Errorf("host/composite: component not available")
	}
	provisioner, ok := p.kinds[comp.TEEKind()]
	if !ok {
		return nil, fmt.Errorf("host/composite: provisioner for kind '%s' is not available", comp.TEEKind())
	}
	return provisioner.NewRuntime(cfg)
}

// Implements host.Provisioner.
func (p *provisioner) Name() string {
	if len(p.kinds) == 0 {
		return "composite{}"
	}

	atoms := make([]string, 0, len(p.kinds))
	for kind, provisioner := range p.kinds {
		atoms = append(atoms, kind.String()+": "+provisioner.Name())
	}
	// Ensure deterministic order.
	slices.Sort(atoms)

	return "composite{" + strings.Join(atoms, ", ") + "}"
}
