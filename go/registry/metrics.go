package registry

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"
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
	registryContracts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "ekiden_registry_contracts",
			Help: "Number of registry contracts.",
		},
	)
	registeryCollectors = []prometheus.Collector{
		registryFailures,
		registryNodes,
		registryEntities,
		registryContracts,
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

func (w *metricsWrapper) RegisterContract(ctx context.Context, sigCon *contract.SignedContract) error {
	if err := w.Backend.RegisterContract(ctx, sigCon); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerContract"}).Inc()
		return err
	}

	registryContracts.Inc()
	return nil
}

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(registeryCollectors...)
	})

	// XXX: When the registry backends support node deregistration,
	// handle this on the metrics side.

	return &metricsWrapper{Backend: base}
}
