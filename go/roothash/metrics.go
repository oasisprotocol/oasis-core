package roothash

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
)

var (
	rootHashFinalizedRounds = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oasis_finalized_rounds",
			Help: "Number of finalized rounds.",
		},
	)
	rootHashBlockInterval = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_roothash_block_interval",
			Help: "Time between roothash blocks (seconds).",
		},
		[]string{"runtime"},
	)
	rootHashCollectors = []prometheus.Collector{
		rootHashFinalizedRounds,
		rootHashBlockInterval,
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

	lastBlockTime := make(map[common.Namespace]time.Time)
	for {
		blk, ok := <-ch
		if !ok {
			break
		}

		if ts, ok := lastBlockTime[blk.Header.Namespace]; ok {
			rootHashBlockInterval.With(prometheus.Labels{
				"runtime": blk.Header.Namespace.String(),
			}).Observe(time.Since(ts).Seconds())
		}
		lastBlockTime[blk.Header.Namespace] = time.Now()

		rootHashFinalizedRounds.Inc()
	}
}

// NewMetricsWrapper wraps a roothash backend implementation with instrumentation.
func NewMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(rootHashCollectors...)
	})

	w := &metricsWrapper{Backend: base}
	go w.worker()

	return w
}
