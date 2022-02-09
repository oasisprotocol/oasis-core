package committee

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	storageWorkerLastFullRound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_storage_full_round",
			Help: "The last round that was fully synced and finalized.",
		},
		[]string{"runtime"},
	)

	storageWorkerLastSyncedRound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_storage_synced_round",
			Help: "The last round that was synced but not yet finalized.",
		},
		[]string{"runtime"},
	)

	storageWorkerLastPendingRound = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_storage_pending_round",
			Help: "The last round that is in-flight for syncing.",
		},
		[]string{"runtime"},
	)

	storageWorkerRoundSyncLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_storage_round_sync_latency",
			Help: "Storage round sync latency (seconds).",
		},
		[]string{"runtime"},
	)

	storageWorkerCollectors = []prometheus.Collector{
		storageWorkerLastFullRound,
		storageWorkerLastSyncedRound,
		storageWorkerLastPendingRound,
		storageWorkerRoundSyncLatency,
	}

	prometheusOnce sync.Once
)

func (n *Node) getMetricLabels() prometheus.Labels {
	return prometheus.Labels{
		"runtime": n.commonNode.Runtime.ID().String(),
	}
}

func initMetrics() {
	prometheusOnce.Do(func() {
		prometheus.MustRegister(storageWorkerCollectors...)
	})
}
