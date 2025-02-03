// Package composite implements support for runtimes composed of multiple components, like having
// both on-chain and off-chain logic.
package composite

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/multi"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type Host struct {
	mu sync.RWMutex

	id common.Namespace

	running bool

	ronl  *multi.Aggregate
	comps map[component.ID]*multi.Aggregate

	logger *logging.Logger
}

// NewHost creates a new composite runtime host that consists of one aggregated
// RONL component runtime host and zero or more aggregated ROFL component
// runtime hosts.
func NewHost(id common.Namespace) *Host {
	ronl := multi.New(id)
	comps := map[component.ID]*multi.Aggregate{
		component.ID_RONL: ronl,
	}

	return &Host{
		id:     id,
		ronl:   ronl,
		comps:  comps,
		logger: logging.GetLogger("runtime/host/composite").With("runtime_id", id),
	}
}

// ID implements host.Runtime.
func (h *Host) ID() common.Namespace {
	return h.id
}

// GetActiveVersion implements host.Runtime.
func (h *Host) GetActiveVersion() (*version.Version, error) {
	return h.ronl.GetActiveVersion()
}

// GetInfo implements host.Runtime.
func (h *Host) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	return h.ronl.GetInfo(ctx)
}

// GetCapabilityTEE implements host.Runtime.
func (h *Host) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	return h.ronl.GetCapabilityTEE()
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

// Call implements host.Runtime.
func (h *Host) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result, err := h.ronl.Call(ctx, body)
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

// UpdateCapabilityTEE implements host.Runtime.
func (h *Host) UpdateCapabilityTEE() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, comp := range h.comps {
		comp.UpdateCapabilityTEE()
	}
}

// WatchEvents implements host.Runtime.
func (h *Host) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	return h.ronl.WatchEvents()
}

// Start implements host.Runtime.
func (h *Host) Start() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, comp := range h.comps {
		comp.Start()
	}
	h.running = true
}

// Abort implements host.Runtime.
func (h *Host) Abort(ctx context.Context, force bool) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Only RONL supports aborts.
	return h.ronl.Abort(ctx, force)
}

// Stop implements host.Runtime.
func (h *Host) Stop() {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, comp := range h.comps {
		comp.Stop()
	}
	h.running = false
}

// Component implements host.CompositeRuntime.
func (h *Host) Component(id component.ID) (*multi.Aggregate, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	comp, ok := h.comps[id]
	return comp, ok
}

// Components returns all runtime component hosts.
func (h *Host) Components() map[component.ID]*multi.Aggregate {
	h.mu.RLock()
	defer h.mu.RUnlock()

	return maps.Clone(h.comps)
}

// HasVersion checks if the runtime component host exists for the given version.
func (h *Host) HasVersion(id component.ID, version version.Version) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	comp, ok := h.comps[id]
	if !ok {
		return false
	}
	return comp.HasVersion(version)
}

// AddVersion adds a new version of the runtime component.
func (h *Host) AddVersion(id component.ID, version version.Version, rt host.Runtime) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.logger.Info("adding version",
		"id", id,
		"version", version,
	)

	comp, ok := h.comps[id]
	if !ok {
		comp = multi.New(h.id)
		if h.running {
			comp.Start()
		}
		h.comps[id] = comp
	}

	if err := comp.AddVersion(version, rt); err != nil {
		return err
	}

	h.logger.Info("version added",
		"id", id,
		"version", version,
	)

	return nil
}

// RemoveComponent removes a specific runtime component.
//
// Attempting to remove the RONL component will result in an error.
func (h *Host) RemoveComponent(id component.ID) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if id == component.ID_RONL {
		return fmt.Errorf("RONL component cannot be removed")
	}

	h.logger.Info("removing component",
		"id", id,
	)

	comp, ok := h.comps[id]
	if !ok {
		return nil
	}

	comp.Stop()
	delete(h.comps, id)

	h.logger.Info("component removed",
		"id", id,
	)

	return nil
}
