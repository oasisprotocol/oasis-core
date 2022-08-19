package txpool

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	pendingCheckSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_txpool_pending_check_size",
			Help: "Size of the pending to be checked queue (number of entries).",
		},
		[]string{"runtime"},
	)
	mainQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_txpool_pending_schedule_size",
			Help: "Size of the main schedulable queue (number of entries).",
		},
		[]string{"runtime"},
	)
	localQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_txpool_local_queue_size",
			Help: "Size of the local transactions schedulable queue (number of entries).",
		},
		[]string{"runtime"},
	)
	rimQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_txpool_rim_queue_size",
			Help: "Size of the roothash incoming message transactions schedulable queue (number of entries).",
		},
		[]string{"runtime"},
	)
	rejectedTransactions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_txpool_rejected_transactions",
			Help: "Number of rejected transactions (failing check tx).",
		},
		[]string{"runtime"},
	)
	acceptedTransactions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_txpool_accepted_transactions",
			Help: "Number of accepted transactions (passing check tx).",
		},
		[]string{"runtime"},
	)
	txpoolCollectors = []prometheus.Collector{
		pendingCheckSize,
		mainQueueSize,
		localQueueSize,
		rimQueueSize,
		rejectedTransactions,
		acceptedTransactions,
	}

	metricsOnce sync.Once
)

func (t *txPool) getMetricLabels() prometheus.Labels {
	return prometheus.Labels{
		"runtime": t.runtimeID.String(),
	}
}

func initMetrics() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(txpoolCollectors...)
	})
}
