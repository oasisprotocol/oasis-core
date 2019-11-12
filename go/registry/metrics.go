package registry

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/registry/api"
)

const metricsUpdateInterval = 10 * time.Second

var (
	registryFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_registry_failures",
			Help: "Number of registry failures.",
		},
		[]string{"call"},
	)
	registryNodes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_registry_nodes",
			Help: "Number of registry nodes.",
		},
	)
	registryEntities = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_registry_entities",
			Help: "Number of registry entities.",
		},
	)
	registryRuntimes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "oasis_registry_runtimes",
			Help: "Number of registry runtimes.",
		},
	)
	registeryCollectors = []prometheus.Collector{
		registryFailures,
		registryNodes,
		registryEntities,
		registryRuntimes,
	}

	_ api.Backend = (*metricsWrapper)(nil)

	metricsOnce sync.Once
)

type metricsWrapper struct {
	api.Backend

	closeOnce sync.Once
	closeCh   chan struct{}
	closedCh  chan struct{}
}

func (w *metricsWrapper) RegisterEntity(ctx context.Context, sigEnt *entity.SignedEntity) error {
	if err := w.Backend.RegisterEntity(ctx, sigEnt); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerEntity"}).Inc()
		return err
	}

	return nil
}

func (w *metricsWrapper) DeregisterEntity(ctx context.Context, sigTimestamp *signature.Signed) error {
	if err := w.Backend.DeregisterEntity(ctx, sigTimestamp); err != nil {
		registryFailures.With(prometheus.Labels{"call": "deregisterEntity"}).Inc()
		return err
	}

	return nil
}

func (w *metricsWrapper) RegisterNode(ctx context.Context, sigNode *node.SignedNode) error {
	if err := w.Backend.RegisterNode(ctx, sigNode); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerNode"}).Inc()
		return err
	}

	return nil
}

func (w *metricsWrapper) RegisterRuntime(ctx context.Context, sigCon *api.SignedRuntime) error {
	if err := w.Backend.RegisterRuntime(ctx, sigCon); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerRuntime"}).Inc()
		return err
	}

	return nil
}

func (w *metricsWrapper) GetNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	return w.Backend.GetNodeList(ctx, height)
}

func (w *metricsWrapper) GetRuntimes(ctx context.Context, height int64) ([]*api.Runtime, error) {
	return w.Backend.GetRuntimes(ctx, height)
}

func (w *metricsWrapper) Cleanup() {
	w.closeOnce.Do(func() {
		close(w.closeCh)
		<-w.closedCh
	})

	w.Backend.Cleanup()
}

func (w *metricsWrapper) worker(ctx context.Context) {
	defer close(w.closedCh)

	t := time.NewTicker(metricsUpdateInterval)
	defer t.Stop()

	runtimeCh, sub := w.Backend.WatchRuntimes()
	defer sub.Close()

	for {
		select {
		case <-w.closeCh:
			return
		case <-runtimeCh:
			registryRuntimes.Inc()
			continue
		case <-t.C:
		}

		w.updatePeriodicMetrics(ctx)
	}
}

func (w *metricsWrapper) updatePeriodicMetrics(ctx context.Context) {
	nodes, err := w.Backend.GetNodes(ctx, 0)
	if err == nil {
		registryNodes.Set(float64(len(nodes)))
	}

	entities, err := w.Backend.GetEntities(ctx, 0)
	if err == nil {
		registryEntities.Set(float64(len(entities)))
	}
}

// NewMetricsWrapper wraps a registry backend implementation with instrumentation.
func NewMetricsWrapper(ctx context.Context, base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(registeryCollectors...)
	})

	// XXX: When the registry backends support node deregistration,
	// handle this on the metrics side.

	wrapper := &metricsWrapper{
		Backend:  base,
		closeCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}

	wrapper.updatePeriodicMetrics(ctx)
	go wrapper.worker(ctx)

	return wrapper
}
