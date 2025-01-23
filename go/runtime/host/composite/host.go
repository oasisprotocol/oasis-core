// Package composite implements support for runtimes composed of multiple components, like having
// both on-chain and off-chain logic.
package composite

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type compositeHost struct {
	id      common.Namespace
	version version.Version
	comps   map[component.ID]host.Runtime

	stopCh chan struct{}

	logger *logging.Logger
}

// NewHost creates a new composite runtime host.
func NewHost(id common.Namespace, version version.Version, comps map[component.ID]host.Runtime) host.Runtime {
	return &compositeHost{
		id:      id,
		version: version,
		comps:   comps,
		stopCh:  make(chan struct{}),
		logger:  logging.GetLogger("runtime/host/composite").With("runtime_id", id),
	}
}

// Implements host.Runtime.
func (h *compositeHost) ID() common.Namespace {
	return h.id
}

// Implements host.Runtime.
func (h *compositeHost) GetActiveVersion() (*version.Version, error) {
	return h.comps[component.ID_RONL].GetActiveVersion()
}

// Implements host.Runtime.
func (h *compositeHost) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	return h.comps[component.ID_RONL].GetInfo(ctx)
}

// Implements host.Runtime.
func (h *compositeHost) GetCapabilityTEE() (*node.CapabilityTEE, error) {
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
func (h *compositeHost) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
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
func (h *compositeHost) UpdateCapabilityTEE() {
	for _, comp := range h.comps {
		comp.UpdateCapabilityTEE()
	}
}

// Implements host.Runtime.
func (h *compositeHost) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	return h.comps[component.ID_RONL].WatchEvents()
}

// Implements host.Runtime.
func (h *compositeHost) Start() {
	for _, comp := range h.comps {
		comp.Start()
	}
}

// Implements host.Runtime.
func (h *compositeHost) Abort(ctx context.Context, force bool) error {
	// Only RONL supports aborts.
	return h.comps[component.ID_RONL].Abort(ctx, force)
}

// Implements host.Runtime.
func (h *compositeHost) Stop() {
	close(h.stopCh)

	for _, comp := range h.comps {
		comp.Stop()
	}
}

// Implements host.CompositeRuntime.
func (h *compositeHost) Component(id component.ID) (host.Runtime, bool) {
	comp, ok := h.comps[id]
	return comp, ok
}
