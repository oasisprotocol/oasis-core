package roothash

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/roothash/api"
)

var (
	rootHashFinalizedRounds = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_finalized_rounds",
			Help: "Number of finalized rounds",
		},
	)
	rootHashCollectors = []prometheus.Collector{
		rootHashFinalizedRounds,
	}

	_ api.Backend = (*metricsWrapper)(nil)

	metricsOnce sync.Once
)

type metricsWrapper struct {
	api.Backend
}

func (w *metricsWrapper) worker() {
	backend, ok := w.Backend.(api.MetricsMonitorable)
	if !ok {
		return
	}

	ch, sub := backend.WatchAllBlocks()
	defer sub.Close()

	for {
		if _, ok := <-ch; !ok {
			break
		}

		rootHashFinalizedRounds.Inc()
	}
}

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(rootHashCollectors...)
	})

	w := &metricsWrapper{Backend: base}
	go w.worker()

	return w
}
