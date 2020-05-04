package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	SignedBlocks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_consensus_signed_blocks",
			Help: "Number of blocks signed by the node.",
		},
		[]string{"backend"},
	)
	ProposedBlocks = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_consensus_proposed_blocks",
			Help: "Number of blocks proposed by the node.",
		},
		[]string{"backend"},
	)

	consensusCollectors = []prometheus.Collector{
		SignedBlocks,
		ProposedBlocks,
	}

	metricsOnce sync.Once
)

func init() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(consensusCollectors...)
	})
}
