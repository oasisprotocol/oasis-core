package keymanager

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	computeRuntimeCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oasis_worker_keymanager_compute_runtime_count",
			Help: "Number of compute runtimes using the key manager.",
		},
	)

	policyUpdateCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "oasis_worker_keymanager_policy_update_count",
			Help: "Number of key manager policy updates.",
		},
	)

	keymanagerWorkerCollectors = []prometheus.Collector{
		computeRuntimeCount,
		policyUpdateCount,
	}

	metricsOnce sync.Once
)

func initMetrics() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(keymanagerWorkerCollectors...)
	})
}
