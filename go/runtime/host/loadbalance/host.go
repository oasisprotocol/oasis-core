// Package loadbalance implements a runtime provisioner that internally load-balances requests among
// multiple runtime instances. This is especially useful on client nodes handling queries.
package loadbalance

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type lbHost struct {
	id        common.Namespace
	instances []host.Runtime

	l                sync.Mutex
	nextIdx          int
	healthyInstances map[int]struct{}

	startOnce sync.Once
	stopOnce  sync.Once
	stopCh    chan struct{}

	logger *logging.Logger
}

// NewHost creates a new load balancer runtime host.
func NewHost(id common.Namespace, instances []host.Runtime) host.Runtime {
	return &lbHost{
		id:               id,
		instances:        instances,
		healthyInstances: make(map[int]struct{}),
		stopCh:           make(chan struct{}),
		logger:           logging.GetLogger("runtime/host/loadbalance").With("runtime_id", id),
	}
}

// Implements host.Runtime.
func (h *lbHost) ID() common.Namespace {
	return h.id
}

// Implements host.Runtime.
func (h *lbHost) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	return h.instances[0].GetInfo(ctx)
}

// Implements host.Runtime.
func (h *lbHost) GetActiveVersion() (*version.Version, error) {
	return h.instances[0].GetActiveVersion()
}

// Implements host.Runtime.
func (h *lbHost) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	// TODO: This won't work when registration of all client runtimes is required.
	return h.instances[0].GetCapabilityTEE()
}

// shouldPropagateToAll checks whether the given runtime request should be propagated to all
// instances.
func shouldPropagateToAll(body *protocol.Body) bool {
	switch {
	case body.RuntimeConsensusSyncRequest != nil:
		// Consensus view of all instances should be up to date as otherwise signed attestations
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
func (h *lbHost) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	switch {
	case shouldPropagateToAll(body):
		// Propagate call to all instances.
		type result struct {
			rsp *protocol.Body
			err error
		}
		resCh := make(chan *result)
		for _, rt := range h.instances {
			go func() {
				rsp, err := rt.Call(ctx, body)
				resCh <- &result{
					rsp: rsp,
					err: err,
				}
			}()
		}

		var (
			anyErr error
			rsp    *protocol.Body
		)
		for range h.instances {
			res := <-resCh
			// Return the response of the instance that finished last. Note that currently all of
			// the propagated methods return a `protocol.Empty` response so this does not matter.
			rsp = res.rsp
			anyErr = errors.Join(anyErr, res.err)
		}
		if anyErr != nil {
			return nil, anyErr
		}
		return rsp, nil
	case body.RuntimeQueryRequest != nil, body.RuntimeCheckTxBatchRequest != nil:
		// Load-balance queries.
		idx, err := h.selectInstance()
		if err != nil {
			return nil, err
		}

		lbRequestCount.With(prometheus.Labels{
			"runtime":     h.id.String(),
			"lb_instance": fmt.Sprintf("%d", idx),
		}).Inc()

		return h.instances[idx].Call(ctx, body)
	default:
		// Propagate only to the first instance.
		return h.instances[0].Call(ctx, body)
	}
}

func (h *lbHost) selectInstance() (int, error) {
	h.l.Lock()
	defer h.l.Unlock()

	for attempt := 0; attempt < len(h.instances); attempt++ {
		idx := h.nextIdx
		h.nextIdx = (h.nextIdx + 1) % len(h.instances)

		if _, healthy := h.healthyInstances[idx]; healthy {
			return idx, nil
		}
	}

	return 0, fmt.Errorf("host/loadbalance: no healthy instances available")
}

// Implements host.Runtime.
func (h *lbHost) UpdateCapabilityTEE() {
	for _, rt := range h.instances {
		rt.UpdateCapabilityTEE()
	}
}

// Implements host.Runtime.
func (h *lbHost) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	return h.instances[0].WatchEvents()
}

// Implements host.Runtime.
func (h *lbHost) Start() {
	h.startOnce.Do(func() {
		for idx, rt := range h.instances {
			// Subscribe to runtime events before starting runtime to make sure we don't miss the
			// started event.
			evCh, sub := rt.WatchEvents()

			// Start a goroutine to monitor whether an instance is healthy.
			go func() {
				defer sub.Close()

				for {
					select {
					case ev := <-evCh:
						switch {
						case ev.Started != nil:
							// Mark instance as available.
							h.logger.Info("instance is available",
								"instance", idx,
							)

							h.l.Lock()
							h.healthyInstances[idx] = struct{}{}
							h.l.Unlock()
						case ev.FailedToStart != nil, ev.Stopped != nil:
							// Mark instance as failed.
							h.logger.Warn("instance is no longer available",
								"instance", idx,
							)

							h.l.Lock()
							delete(h.healthyInstances, idx)
							h.l.Unlock()
						default:
						}

						// Update healthy instance count metrics.
						h.l.Lock()
						healthyInstanceCount := len(h.healthyInstances)
						h.l.Unlock()

						lbHealthyInstanceCount.With(prometheus.Labels{
							"runtime": h.id.String(),
						}).Set(float64(healthyInstanceCount))
					case <-h.stopCh:
						return
					}
				}
			}()

			rt.Start()
		}
	})
}

// Implements host.Runtime.
func (h *lbHost) Abort(ctx context.Context, force bool) error {
	// We don't know which instance to abort, so we abort all instances.
	errCh := make(chan error)
	for _, rt := range h.instances {
		go func() {
			errCh <- rt.Abort(ctx, force)
		}()
	}

	var anyErr error
	for range h.instances {
		err := <-errCh
		anyErr = errors.Join(anyErr, err)
	}
	return anyErr
}

// Implements host.Runtime.
func (h *lbHost) Stop() {
	h.stopOnce.Do(func() {
		close(h.stopCh)

		for _, rt := range h.instances {
			rt.Stop()
		}
	})
}
