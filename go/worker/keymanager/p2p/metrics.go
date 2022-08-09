package p2p

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	enclaveRPCCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_keymanager_enclave_rpc_count",
			Help: "Number of remote Enclave RPC requests via P2P.",
		},
		[]string{"method"},
	)

	keymanagerWorkerCollectors = []prometheus.Collector{
		enclaveRPCCount,
	}

	metricsOnce sync.Once
)

func initMetrics() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(keymanagerWorkerCollectors...)
	})
}
