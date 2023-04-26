package sgx

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
)

var (
	// Number of TEE attestations performed.
	teeAttestationsPerformed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_tee_attestations_performed",
			Help: "Number of TEE attestations performed.",
		},
		[]string{"runtime"},
	)

	// Number of successful TEE attestations.
	teeAttestationsSuccessful = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_tee_attestations_successful",
			Help: "Number of successful TEE attestations.",
		},
		[]string{"runtime"},
	)

	// Number of failed TEE attestations.
	teeAttestationsFailed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_tee_attestations_failed",
			Help: "Number of failed TEE attestations.",
		},
		[]string{"runtime"},
	)

	teeCollectors = []prometheus.Collector{
		teeAttestationsPerformed,
		teeAttestationsSuccessful,
		teeAttestationsFailed,
	}

	metricsOnce sync.Once
)

// updateAttestationMetrics updates the attestation metrics if metrics are enabled.
func updateAttestationMetrics(runtime string, err error) {
	if !metrics.Enabled() {
		return
	}

	teeAttestationsPerformed.With(prometheus.Labels{"runtime": runtime}).Inc()
	if err != nil {
		teeAttestationsFailed.With(prometheus.Labels{"runtime": runtime}).Inc()
	} else {
		teeAttestationsSuccessful.With(prometheus.Labels{"runtime": runtime}).Inc()
	}
}

// initMetrics registers the metrics collectors if metrics are enabled.
func initMetrics() {
	if !metrics.Enabled() {
		return
	}

	metricsOnce.Do(func() {
		prometheus.MustRegister(teeCollectors...)
	})
}
