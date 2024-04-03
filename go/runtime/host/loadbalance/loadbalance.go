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
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// Config is the configuration for the runtime load balancer.
type Config struct {
	// NumInstances is the number of runtime instances to provision.
	NumInstances int
}

type lbRuntime struct {
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

// Implements host.Runtime.
func (lb *lbRuntime) ID() common.Namespace {
	return lb.id
}

// Implements host.Runtime.
func (lb *lbRuntime) GetInfo(ctx context.Context) (*protocol.RuntimeInfoResponse, error) {
	return lb.instances[0].GetInfo(ctx)
}

// Implements host.Runtime.
func (lb *lbRuntime) GetActiveVersion() (*version.Version, error) {
	return lb.instances[0].GetActiveVersion()
}

// Implements host.Runtime.
func (lb *lbRuntime) GetCapabilityTEE() (*node.CapabilityTEE, error) {
	// TODO: This won't work when registration of all client runtimes is required.
	return lb.instances[0].GetCapabilityTEE()
}

// shouldPropagateToAll checks whether the given runtime request should be propagated to all
// instances.
func shouldPropagateToAll(body *protocol.Body) bool {
	switch {
	case body.RuntimeConsensusSyncRequest != nil:
		// Consensus view of all instances should be up to date as otherwise signed attestations
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
func (lb *lbRuntime) Call(ctx context.Context, body *protocol.Body) (*protocol.Body, error) {
	switch {
	case shouldPropagateToAll(body):
		// Propagate call to all instances.
		type result struct {
			rsp *protocol.Body
			err error
		}
		resCh := make(chan *result)
		for _, rt := range lb.instances {
			rt := rt // Make sure goroutine below operates on the right instance.

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
		for range lb.instances {
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
		idx, err := lb.selectInstance()
		if err != nil {
			return nil, err
		}

		lbRequestCount.With(prometheus.Labels{
			"runtime":     lb.id.String(),
			"lb_instance": fmt.Sprintf("%d", idx),
		}).Inc()

		return lb.instances[idx].Call(ctx, body)
	default:
		// Propagate only to the first instance.
		return lb.instances[0].Call(ctx, body)
	}
}

func (lb *lbRuntime) selectInstance() (int, error) {
	lb.l.Lock()
	defer lb.l.Unlock()

	for attempt := 0; attempt < len(lb.instances); attempt++ {
		idx := lb.nextIdx
		lb.nextIdx = (lb.nextIdx + 1) % len(lb.instances)

		if _, healthy := lb.healthyInstances[idx]; healthy {
			return idx, nil
		}
	}

	return 0, fmt.Errorf("host/loadbalance: no healthy instances available")
}

// Implements host.Runtime.
func (lb *lbRuntime) UpdateCapabilityTEE() {
	for _, rt := range lb.instances {
		rt.UpdateCapabilityTEE()
	}
}

// Implements host.Runtime.
func (lb *lbRuntime) WatchEvents() (<-chan *host.Event, pubsub.ClosableSubscription) {
	return lb.instances[0].WatchEvents()
}

// Implements host.Runtime.
func (lb *lbRuntime) Start() {
	lb.startOnce.Do(func() {
		for idx, rt := range lb.instances {
			idx := idx
			rt := rt // Make sure goroutine below operates on the right instance.

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
							lb.logger.Info("instance is available",
								"instance", idx,
							)

							lb.l.Lock()
							lb.healthyInstances[idx] = struct{}{}
							lb.l.Unlock()
						case ev.FailedToStart != nil, ev.Stopped != nil:
							// Mark instance as failed.
							lb.logger.Warn("instance is no longer available",
								"instance", idx,
							)

							lb.l.Lock()
							delete(lb.healthyInstances, idx)
							lb.l.Unlock()
						default:
						}

						// Update healthy instance count metrics.
						lb.l.Lock()
						healthyInstanceCount := len(lb.healthyInstances)
						lb.l.Unlock()

						lbHealthyInstanceCount.With(prometheus.Labels{
							"runtime": lb.id.String(),
						}).Set(float64(healthyInstanceCount))
					case <-lb.stopCh:
						return
					}
				}
			}()

			rt.Start()
		}
	})
}

// Implements host.Runtime.
func (lb *lbRuntime) Abort(ctx context.Context, force bool) error {
	// We don't know which instance to abort, so we abort all instances.
	errCh := make(chan error)
	for _, rt := range lb.instances {
		rt := rt // Make sure goroutine below operates on the right instance.

		go func() {
			errCh <- rt.Abort(ctx, force)
		}()
	}

	var anyErr error
	for range lb.instances {
		err := <-errCh
		anyErr = errors.Join(anyErr, err)
	}
	return anyErr
}

// Implements host.Runtime.
func (lb *lbRuntime) Stop() {
	lb.stopOnce.Do(func() {
		close(lb.stopCh)

		for _, rt := range lb.instances {
			rt.Stop()
		}
	})
}

type lbProvisioner struct {
	inner host.Provisioner
	cfg   Config
}

// Implements host.Provisioner.
func (lb *lbProvisioner) NewRuntime(cfg host.Config) (host.Runtime, error) {
	if lb.cfg.NumInstances < 2 {
		// This should never happen as the provisioner constructor made sure, but just to be safe.
		return nil, fmt.Errorf("host/loadbalance: number of instances must be at least two")
	}

	// The load-balancer can only be used for the RONL component. For others, do pass-through.
	if len(cfg.Components) != 1 {
		return nil, fmt.Errorf("host/loadbalance: must specify a single component")
	}
	if cfg.Components[0] != bundle.ComponentID_RONL {
		return lb.inner.NewRuntime(cfg)
	}

	// Use the inner provisioner to provision multiple runtimes.
	var instances []host.Runtime
	for i := 0; i < lb.cfg.NumInstances; i++ {
		rt, err := lb.inner.NewRuntime(cfg)
		if err != nil {
			return nil, fmt.Errorf("host/loadbalance: failed to provision instance %d: %w", i, err)
		}

		instances = append(instances, rt)
	}

	return &lbRuntime{
		id:               cfg.Bundle.Manifest.ID,
		instances:        instances,
		healthyInstances: make(map[int]struct{}),
		stopCh:           make(chan struct{}),
		logger:           logging.GetLogger("runtime/host/loadbalance").With("runtime_id", cfg.Bundle.Manifest.ID),
	}, nil
}

// Implements host.Provisioner.
func (lb *lbProvisioner) Name() string {
	return fmt.Sprintf("load-balancer[%d]/%s", lb.cfg.NumInstances, lb.inner.Name())
}

// New creates a load-balancing runtime provisioner.
func New(inner host.Provisioner, cfg Config) host.Provisioner {
	if cfg.NumInstances < 2 {
		// If there is only a single instance configured just return the inner provisioner.
		return inner
	}

	initMetrics()

	return &lbProvisioner{
		inner: inner,
		cfg:   cfg,
	}
}
