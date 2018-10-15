package registry

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/registry/api"
)

var (
	registryFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_registry_failures",
			Help: "Number of registry failures.",
		},
		[]string{"call"},
	)
	registryNodes = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_registry_nodes",
			Help: "Number of registry nodes.",
		},
	)
	registryEntities = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ekiden_registry_entities",
			Help: "Number of registry entities.",
		},
	)
	registryRuntimes = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ekiden_registry_runtimes",
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
}

func (w *metricsWrapper) RegisterEntity(ctx context.Context, sigEnt *entity.SignedEntity) error {
	if err := w.Backend.RegisterEntity(ctx, sigEnt); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerEntity"}).Inc()
		return err
	}

	registryEntities.Inc()
	return nil
}

func (w *metricsWrapper) DeregisterEntity(ctx context.Context, sigID *signature.SignedPublicKey) error {
	if err := w.Backend.DeregisterEntity(ctx, sigID); err != nil {
		registryFailures.With(prometheus.Labels{"call": "deregisterEntity"}).Inc()
		return err
	}

	registryEntities.Dec()
	return nil
}

func (w *metricsWrapper) RegisterNode(ctx context.Context, sigNode *node.SignedNode) error {
	if err := w.Backend.RegisterNode(ctx, sigNode); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerNode"}).Inc()
		return err
	}

	registryNodes.Inc()
	return nil
}

func (w *metricsWrapper) RegisterRuntime(ctx context.Context, sigCon *runtime.SignedRuntime) error {
	if err := w.Backend.RegisterRuntime(ctx, sigCon); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerRuntime"}).Inc()
		return err
	}

	registryRuntimes.Inc()
	return nil
}

type blockMetricsWrapper struct {
	metricsWrapper
	blockBackend api.BlockBackend
}

func (w *blockMetricsWrapper) GetBlockNodeList(ctx context.Context, height int64) (*api.NodeList, error) {
	return w.blockBackend.GetBlockNodeList(ctx, height)
}

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(registeryCollectors...)
	})

	// XXX: When the registry backends support node deregistration,
	// handle this on the metrics side.

	wrapper := metricsWrapper{Backend: base}

	blockBackend, ok := base.(api.BlockBackend)
	if ok {
		return &blockMetricsWrapper{
			metricsWrapper: wrapper,
			blockBackend:   blockBackend,
		}
	}

	return &wrapper
}
