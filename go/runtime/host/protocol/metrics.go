package protocol

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
)

var (
	rhpLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_rhp_latency",
			Help: "Runtime Host call latency (seconds).",
		},
		[]string{"call"},
	)
	rhpCallSuccesses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_rhp_successes",
			Help: "Number of successful Runtime Host calls.",
		},
		[]string{"call"},
	)
	rhpCallFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_rhp_failures",
			Help: "Number of failed Runtime Host calls.",
		},
		[]string{"call"},
	)
	rhpCallTimeouts = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oasis_rhp_timeouts",
			Help: "Number of timed out Runtime Host calls.",
		},
	)

	rhpCollectors = []prometheus.Collector{
		rhpLatency,
		rhpCallSuccesses,
		rhpCallFailures,
		rhpCallTimeouts,
	}

	metricsOnce sync.Once
)

// initMetrics registers the metrics collectors.
func initMetrics() {
	if !metrics.Enabled() {
		return
	}

	metricsOnce.Do(func() {
		prometheus.MustRegister(rhpCollectors...)
	})
}
