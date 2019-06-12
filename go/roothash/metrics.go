package roothash

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
)

var (
	rootHashFinalizedRounds = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_finalized_rounds",
			Help: "Number of finalized rounds",
		},
	)
	rootHashBlockInterval = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_roothash_block_interval",
			Help: "Time between roothash blocks",
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

func (w *metricsWrapper) WatchAnnotatedBlocks(id signature.PublicKey) (<-chan *api.AnnotatedBlock, *pubsub.Subscription, error) {
	return w.Backend.WatchAnnotatedBlocks(id)
}

func (w *metricsWrapper) worker() {
	backend, ok := w.Backend.(api.MetricsMonitorable)
	if !ok {
		return
	}

	ch, sub := backend.WatchAllBlocks()
	defer sub.Close()

	lastBlockTime := make(map[block.Namespace]time.Time)
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

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(rootHashCollectors...)
	})

	w := &metricsWrapper{Backend: base}
	go w.worker()

	return w
}
