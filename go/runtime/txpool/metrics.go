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
	pendingScheduleSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_txpool_pending_schedule_size",
			Help: "Size of the pending to be scheduled queue (number of entries).",
		},
		[]string{"runtime"},
	)
	txpoolCollectors = []prometheus.Collector{
		pendingCheckSize,
		pendingScheduleSize,
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
