package registry

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/registry/api"
)

const metricsUpdateInterval = 10 * time.Second

var (
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
		registryNodes,
		registryEntities,
		registryRuntimes,
	}

	metricsOnce sync.Once
)

// MetricsUpdater is a registry metric updater.
type MetricsUpdater struct {
	logger *logging.Logger

	backend api.Backend

	closeOnce sync.Once
	closeCh   chan struct{}
	closedCh  chan struct{}
}

// Cleanup performs cleanup.
func (m *MetricsUpdater) Cleanup() {
	m.closeOnce.Do(func() {
		close(m.closeCh)
		<-m.closedCh
	})
}

func (m *MetricsUpdater) worker(ctx context.Context) {
	defer close(m.closedCh)

	t := time.NewTicker(metricsUpdateInterval)
	defer t.Stop()

	runtimeCh, sub, err := m.backend.WatchRuntimes(ctx)
	if err != nil {
		m.logger.Error("failed to watch runtimes, metrics will not be updated",
			"err", err,
		)
		return
	}
	defer sub.Close()

	for {
		select {
		case <-m.closeCh:
			return
		case <-runtimeCh:
			registryRuntimes.Inc()
			continue
		case <-t.C:
		}

		m.updatePeriodicMetrics(ctx)
	}
}

func (m *MetricsUpdater) updatePeriodicMetrics(ctx context.Context) {
	nodes, err := m.backend.GetNodes(ctx, consensus.HeightLatest)
	if err == nil {
		registryNodes.Set(float64(len(nodes)))
	}

	entities, err := m.backend.GetEntities(ctx, consensus.HeightLatest)
	if err == nil {
		registryEntities.Set(float64(len(entities)))
	}
}

// NewMetricsUpdater creates a new registry metrics updater.
func NewMetricsUpdater(ctx context.Context, backend api.Backend) *MetricsUpdater {
	metricsOnce.Do(func() {
		prometheus.MustRegister(registeryCollectors...)
	})

	m := &MetricsUpdater{
		logger:   logging.GetLogger("go/registry/metrics"),
		backend:  backend,
		closeCh:  make(chan struct{}),
		closedCh: make(chan struct{}),
	}

	m.updatePeriodicMetrics(ctx)
	go m.worker(ctx)

	return m
}
