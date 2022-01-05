package p2p

import (
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// CfgP2pPort configures the P2P port.
	CfgP2pPort = "worker.p2p.port"

	cfgP2pAddresses = "worker.p2p.addresses"

	// CfgP2PPeerOutboundQueueSize sets the libp2p gossipsub buffer size for outbound messages.
	CfgP2PPeerOutboundQueueSize = "worker.p2p.peer_outbound_queue_size"
	// CfgP2PValidateQueueSize sets the libp2p gossipsub buffer size of the validate queue.
	CfgP2PValidateQueueSize = "worker.p2p.validate_queue_size"
	// CfgP2PValidateConcurrency sets the libp2p gossipsub per topic validator concurrency limit.
	// Note: this is a per-topic concurrency limit. We use one topic per runtime.
	CfgP2PValidateConcurrency = "worker.p2p.validate_concurrency"
	// CfgP2PValidateThrottle sets the libp2p gossipsub validator concurrency limit.
	// Note: this is a global (across all topics) validator concurrency limit.
	CfgP2PValidateThrottle = "worker.p2p.validate_throttle"
	// CfgP2PConnectednessLowWater sets the ratio of connected to unconnected peers at which
	// the peer manager will try to reconnect to disconnected nodes.
	CfgP2PConnectednessLowWater = "worker.p2p.connectedness_low_water"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

func init() {
	Flags.Uint16(CfgP2pPort, 9200, "Port to use for incoming P2P connections")
	Flags.StringSlice(cfgP2pAddresses, []string{}, "Address/port(s) to use for P2P connections when registering this node (if not set, all non-loopback local interfaces will be used)")
	Flags.Int64(CfgP2PPeerOutboundQueueSize, 32, "Set libp2p gossipsub buffer size for outbound messages")
	Flags.Int64(CfgP2PValidateQueueSize, 32, "Set libp2p gossipsub buffer size of the validate queue")
	Flags.Int64(CfgP2PValidateConcurrency, 1024, "Set libp2p gossipsub per topic validator concurrency limit")
	Flags.Int64(CfgP2PValidateThrottle, 8192, "Set libp2p gossipsub validator concurrency limit")
	Flags.Float64(CfgP2PConnectednessLowWater, 0.2, "Set the low water mark at which the peer manager will try to reconnect to peers")

	_ = viper.BindPFlags(Flags)
}
