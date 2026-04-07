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

func initMetrics() {
	prometheusOnce.Do(func() {
		prometheus.MustRegister(storageWorkerCollectors...)
	})
}

type metrics struct {
	lastFullRound    prometheus.Gauge
	lastSyncedRound  prometheus.Gauge
	lastPendingRound prometheus.Gauge
	roundSyncLatency prometheus.Observer
}

func newMetrics(runtime string) *metrics {
	return &metrics{
		lastFullRound:    storageWorkerLastFullRound.WithLabelValues(runtime),
		lastSyncedRound:  storageWorkerLastSyncedRound.WithLabelValues(runtime),
		lastPendingRound: storageWorkerLastPendingRound.WithLabelValues(runtime),
		roundSyncLatency: storageWorkerRoundSyncLatency.WithLabelValues(runtime),
	}
}
