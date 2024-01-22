package loadbalance

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
)

var (
	lbRequestCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_client_lb_requests",
			Help: "Number of requests processed by the given load balancer instance.",
		},
		[]string{"runtime", "lb_instance"},
	)
	lbHealthyInstanceCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_client_lb_healthy_instance_count",
			Help: "Number of healthy instances in the load balancer.",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		lbRequestCount,
		lbHealthyInstanceCount,
	}

	metricsOnce sync.Once
)

// initMetrics registers the metrics collectors if metrics are enabled.
func initMetrics() {
	if !metrics.Enabled() {
		return
	}

	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})
}
