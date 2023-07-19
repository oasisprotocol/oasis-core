package p2p

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	cmmetrics "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/metrics"
)

const metricsUpdateInterval = 60 * time.Second

var (
	peersMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "oasis_p2p_peers",
		Help: "Number of connected P2P peers.",
	})
	blockedPeersMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "oasis_p2p_blocked_peers",
		Help: "Number of blocked P2P peers.",
	})
	connectionsMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "oasis_p2p_connections",
		Help: "Number of P2P connections.",
	})
	topicsMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "oasis_p2p_topics",
		Help: "Number of supported P2P topics.",
	})
	protocolsMetric = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "oasis_p2p_protocols",
		Help: "Number of supported P2P protocols.",
	})

	p2pCollectors = []prometheus.Collector{
		peersMetric,
		blockedPeersMetric,
		connectionsMetric,
		topicsMetric,
		protocolsMetric,
	}

	metricsOnce sync.Once
)

func (p *p2p) metricsWorker() {
	defer close(p.metricsClosedCh)
	if !cmmetrics.Enabled() {
		return
	}

	metricsOnce.Do(func() {
		prometheus.MustRegister(p2pCollectors...)
	})

	for {
		p.updateMetrics()

		select {
		case <-p.ctx.Done():
			return
		case <-time.After(metricsUpdateInterval):
		}
	}
}

func (p *p2p) updateMetrics() {
	peersMetric.Set(float64(len(p.host.Network().Peers())))
	blockedPeersMetric.Set(float64(len(p.gater.ListBlockedPeers())))
	connectionsMetric.Set(float64(len(p.host.Network().Conns())))
	topicsMetric.Set(float64(len(p.peerMgr.Topics())))
	protocolsMetric.Set(float64(len(p.peerMgr.Protocols())))
}
