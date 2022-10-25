package p2p

import (
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
)

const (
	// CfgHostPort configures the port the libp2p host listens on.
	CfgHostPort = "p2p.port"

	// CfgRegistrationAddresses are P2P addresses used when registering the node.
	CfgRegistrationAddresses = "p2p.registration.addresses"

	// CfgGossipsubPeerOutboundQueueSize sets the libp2p gossipsub buffer size for outbound messages.
	CfgGossipsubPeerOutboundQueueSize = "p2p.gossipsub.peer_outbound_queue_size"
	// CfgGossipsubValidateQueueSize sets the libp2p gossipsub buffer size of the validate queue.
	CfgGossipsubValidateQueueSize = "p2p.gossipsub.validate_queue_size"
	// CfgGossipsubValidateConcurrency sets the libp2p gossipsub per topic validator concurrency limit.
	// Note: this is a per-topic concurrency limit. We use one topic per runtime.
	CfgGossipsubValidateConcurrency = "p2p.gossipsub.validate_concurrency"
	// CfgGossipsubValidateThrottle sets the libp2p gossipsub validator concurrency limit.
	// Note: this is a global (across all topics) validator concurrency limit.
	CfgGossipsubValidateThrottle = "p2p.gossipsub.validate_throttle"

	// CfgPeerMgrConnectednessLowWater sets the ratio of connected to unconnected peers at which
	// the peer manager will try to reconnect to disconnected nodes.
	CfgPeerMgrConnectednessLowWater = "p2p.peer_manager.connectedness_low_water"

	// CfgConnMgrMaxNumPeers is the maximum number of peers.
	CfgConnMgrMaxNumPeers = "p2p.connection_manager.max_num_peers"
	// CfgConnMgrPeerGracePeriod is the peer grace period.
	CfgConnMgrPeerGracePeriod = "p2p.connection_manager.peer_grace_period"
	// CfgConnMgrPersistentPeers is a list of persistent peer node addresses in format P2Ppubkey@IP:port.
	CfgConnMgrPersistentPeers = "p2p.connection_manager.persistent_peers"

	// CfgConnGaterBlockedPeerIPs is a list of blocked peer IP addresses.
	CfgConnGaterBlockedPeerIPs = "p2p.connection_gater.blocked_peers"

	// CfgSeeds configures seed node(s).
	CfgSeeds = "p2p.seeds"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

func init() {
	Flags.Uint16(CfgHostPort, 9200, "Port to use for incoming P2P connections")
	Flags.StringSlice(CfgRegistrationAddresses, []string{}, "Address/port(s) to use for P2P connections when registering this node (if not set, all non-loopback local interfaces will be used)")
	Flags.Int64(CfgGossipsubPeerOutboundQueueSize, 32, "Set libp2p gossipsub buffer size for outbound messages")
	Flags.Int64(CfgGossipsubValidateQueueSize, 32, "Set libp2p gossipsub buffer size of the validate queue")
	Flags.Int64(CfgGossipsubValidateConcurrency, 1024, "Set libp2p gossipsub per topic validator concurrency limit")
	Flags.Int64(CfgGossipsubValidateThrottle, 8192, "Set libp2p gossipsub validator concurrency limit")
	Flags.Float64(CfgPeerMgrConnectednessLowWater, 0.2, "Set the low water mark at which the peer manager will try to reconnect to peers")
	Flags.Uint32(CfgConnMgrMaxNumPeers, 100, "Set maximum number of P2P peers")
	Flags.Duration(CfgConnMgrPeerGracePeriod, 20*time.Second, "Time duration for new peer connections to be immune from pruning")
	Flags.StringSlice(CfgConnGaterBlockedPeerIPs, []string{}, "List of blocked peer IPs")
	Flags.StringSlice(CfgConnMgrPersistentPeers, []string{}, "List of persistent peer node addresses in format P2Ppubkey@IP:port")
	Flags.StringSlice(CfgSeeds, []string{}, "Seed node(s) of the form pubkey@IP:port")

	_ = viper.BindPFlags(Flags)
}
