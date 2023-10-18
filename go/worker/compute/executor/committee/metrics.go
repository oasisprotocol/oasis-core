package committee

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
)

var (
	processedEventCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_processed_event_count",
			Help: "Number of processed roothash events.",
		},
		[]string{"runtime"},
	)
	discrepancyDetectedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_execution_discrepancy_detected_count",
			Help: "Number of detected execute discrepancies.",
		},
		[]string{"runtime"},
	)
	abortedBatchCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_aborted_batch_count",
			Help: "Number of aborted batches.",
		},
		[]string{"runtime"},
	)
	storageCommitLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_storage_commit_latency",
			Help: "Latency of storage commit calls (state + outputs) (seconds).",
		},
		[]string{"runtime"},
	)
	batchProcessingTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_batch_processing_time",
			Help: "Time it takes for a batch to finalize (seconds).",
		},
		[]string{"runtime"},
	)
	batchRuntimeProcessingTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_batch_runtime_processing_time",
			Help: "Time it takes for a batch to be processed by the runtime (seconds).",
		},
		[]string{"runtime"},
	)
	batchSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_batch_size",
			Help: "Number of transactions in a batch.",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		processedEventCount,
		discrepancyDetectedCount,
		abortedBatchCount,
		storageCommitLatency,
		batchProcessingTime,
		batchRuntimeProcessingTime,
		batchSize,
	}

	metricsOnce sync.Once
)

func (n *Node) getMetricLabels() prometheus.Labels {
	return prometheus.Labels{
		"runtime": n.commonNode.Runtime.ID().String(),
	}
}

// initMetrics registers the metrics collectors if metrics are enabled.
func initMetrics() {
	if !metrics.Enabled() {
		return
	}

	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})
}
