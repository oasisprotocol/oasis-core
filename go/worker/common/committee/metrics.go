package committee

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

const periodicMetricsInterval = time.Minute

var (
	processedBlockCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_processed_block_count",
			Help: "Number of processed roothash blocks.",
		},
		[]string{"runtime"},
	)
	failedRoundCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_failed_round_count",
			Help: "Number of failed roothash rounds.",
		},
		[]string{"runtime"},
	)
	committeeTransitionCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_committee_transition_count",
			Help: "Number of committee transitions.",
		},
		[]string{"runtime"},
	)
	epochNumber = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_epoch_number",
			Help: "Current epoch number as seen by the worker.",
		},
		[]string{"runtime"},
	)
	workerIsExecutorWorker = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_is_worker",
			Help: "1 if worker is currently an executor worker, 0 otherwise.",
		},
		[]string{"runtime"},
	)
	workerIsExecutorBackup = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_is_backup_worker",
			Help: "1 if worker is currently an executor backup worker, 0 otherwise.",
		},
		[]string{"runtime"},
	)
	executorCommitteeP2PPeers = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_committee_p2p_peers",
			Help: "Number of executor committee P2P peers.",
		},
		[]string{"runtime"},
	)
	livenessTotalRounds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_liveness_total_rounds",
			Help: "Number of total rounds in last epoch.",
		},
		[]string{"runtime"},
	)
	livenessLiveRounds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_liveness_live_rounds",
			Help: "Number of live rounds in last epoch.",
		},
		[]string{"runtime"},
	)
	livenessRatio = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_executor_liveness_live_ratio",
			Help: "Ratio between live and total rounds. Reports 1 if node is not in committee.",
		},
		[]string{"runtime"},
	)

	nodeCollectors = []prometheus.Collector{
		processedBlockCount,
		failedRoundCount,
		committeeTransitionCount,
		epochNumber,
		// Periodically collected metrics.
		workerIsExecutorWorker,
		workerIsExecutorBackup,
		executorCommitteeP2PPeers,
		livenessTotalRounds,
		livenessLiveRounds,
		livenessRatio,
	}

	metricsOnce sync.Once
)

func (n *Node) metricsWorker() {
	n.logger.Info("delaying metrics worker start until worker is initialized")
	select {
	case <-n.stopCh:
		return
	case <-n.initCh:
	}

	n.logger.Debug("starting metrics worker")

	t := time.NewTicker(periodicMetricsInterval)
	defer t.Stop()

	for {
		select {
		case <-n.stopCh:
			return
		case <-t.C:
		}

		n.updatePeriodicMetrics()
	}
}

func (n *Node) updatePeriodicMetrics() {
	boolToMetricVal := func(b bool) float64 {
		if b {
			return 1.0
		}
		return 0.0
	}

	labels := n.getMetricLabels()

	n.logger.Debug("updating periodic worker node metrics")

	committeeInfo, ok := n.Group.CommitteeInfo()
	if !ok {
		return
	}

	executorCommitteeP2PPeers.With(labels).Set(float64(len(n.P2P.Peers(n.Runtime.ID()))))
	workerIsExecutorWorker.With(labels).Set(boolToMetricVal(committeeInfo.IsWorker()))
	workerIsExecutorBackup.With(labels).Set(boolToMetricVal(committeeInfo.IsBackupWorker()))

	if !committeeInfo.IsMember() {
		// Default to 1 if node is not in committee.
		livenessRatio.With(labels).Set(1.0)
		return
	}

	rs, err := n.Consensus.RootHash().GetRuntimeState(n.ctx, &roothash.RuntimeRequest{
		RuntimeID: n.Runtime.ID(),
		Height:    consensus.HeightLatest,
	})
	if err != nil || rs.LivenessStatistics == nil {
		return
	}

	totalRounds := rs.LivenessStatistics.TotalRounds
	var liveRounds uint64
	for _, index := range committeeInfo.Indices {
		liveRounds += rs.LivenessStatistics.LiveRounds[index]
	}
	livenessTotalRounds.With(labels).Set(float64(totalRounds))
	livenessLiveRounds.With(labels).Set(float64(liveRounds))
	livenessRatio.With(labels).Set(float64(liveRounds) / float64(totalRounds))
}

func (n *Node) getMetricLabels() prometheus.Labels {
	return prometheus.Labels{
		"runtime": n.Runtime.ID().String(),
	}
}
