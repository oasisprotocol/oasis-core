package p2p

import (
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"
	"github.com/multiformats/go-multiaddr"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

// HostConfig describes a set of settings for a host.
type HostConfig struct {
	Signer signature.Signer

	UserAgent  string
	ListenAddr multiaddr.Multiaddr
	Port       uint16

	ConnManagerConfig
	ConnGaterConfig
}

// NewHost constructs a new libp2p host.
func NewHost(cfg *HostConfig) (host.Host, *conngater.BasicConnectionGater, error) {
	id := api.SignerToPrivKey(cfg.Signer)

	// Set up a resource manager so that we can reserve more resources.
	rm, err := NewResourceManager()
	if err != nil {
		return nil, nil, err
	}

	// Set up a connection manager so we can limit the number of connections.
	cm, err := NewConnManager(&cfg.ConnManagerConfig)
	if err != nil {
		return nil, nil, err
	}

	// Set up a connection gater so we can block peers.
	cg, err := NewConnGater(&cfg.ConnGaterConfig)
	if err != nil {
		return nil, nil, err
	}

	host, err := libp2p.New(
		libp2p.UserAgent(cfg.UserAgent),
		libp2p.ListenAddrs(cfg.ListenAddr),
		libp2p.Identity(id),
		libp2p.ResourceManager(rm),
		libp2p.ConnectionManager(cm),
		libp2p.ConnectionGater(cg),
	)
	if err != nil {
		return nil, nil, err
	}

	// We need to return the gater as it is not accessible via the host.
	return host, cg, nil
}

// NewHost constructs a new libp2p host.
func (cfg *HostConfig) NewHost() (host.Host, *conngater.BasicConnectionGater, error) {
	return NewHost(cfg)
}

// Load loads host configuration.
func (cfg *HostConfig) Load() error {
	userAgent := fmt.Sprintf("oasis-core/%s", version.SoftwareVersion)
	port := config.GlobalConfig.P2P.Port

	// Listen for connections on all interfaces.
	listenAddr, err := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
	)
	if err != nil {
		return fmt.Errorf("failed to create multiaddress: %w", err)
	}

	var cmCfg ConnManagerConfig
	if err = cmCfg.Load(); err != nil {
		return fmt.Errorf("failed to load connection manager config: %w", err)
	}

	var cgCfg ConnGaterConfig
	if err = cgCfg.Load(); err != nil {
		return fmt.Errorf("failed to load connection gater config: %w", err)
	}

	cfg.UserAgent = userAgent
	cfg.Port = port
	cfg.ListenAddr = listenAddr
	cfg.ConnManagerConfig = cmCfg
	cfg.ConnGaterConfig = cgCfg

	return nil
}

// ConnManagerConfig describes a set of settings for a connection manager.
type ConnManagerConfig struct {
	MinPeers        int
	MaxPeers        int
	GracePeriod     time.Duration
	PersistentPeers []peer.ID
}

// NewConnManager constructs a new connection manager.
func NewConnManager(cfg *ConnManagerConfig) (*connmgr.BasicConnMgr, error) {
	gracePeriod := connmgr.WithGracePeriod(cfg.GracePeriod)
	cm, err := connmgr.NewConnManager(cfg.MinPeers, cfg.MaxPeers, gracePeriod)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager: %w", err)
	}
	for _, pid := range cfg.PersistentPeers {
		cm.Protect(pid, "")
	}
	return cm, nil
}

// NewConnManager constructs a new connection manager.
func (cfg *ConnManagerConfig) NewConnManager() (*connmgr.BasicConnMgr, error) {
	return NewConnManager(cfg)
}

// Load loads connection manager configuration.
func (cfg *ConnManagerConfig) Load() error {
	persistentPeersMap := make(map[core.PeerID]struct{})
	for _, pp := range config.GlobalConfig.P2P.ConnectionManager.PersistentPeers {
		var addr node.ConsensusAddress
		if err := addr.UnmarshalText([]byte(pp)); err != nil {
			return fmt.Errorf("malformed address (expected pubkey@IP:port): %w", err)
		}

		pid, err := api.PublicKeyToPeerID(addr.ID)
		if err != nil {
			return fmt.Errorf("invalid public key (%s): %w", addr.ID, err)
		}

		persistentPeersMap[pid] = struct{}{}
	}

	persistentPeers := make([]peer.ID, 0)
	for pid := range persistentPeersMap {
		persistentPeers = append(persistentPeers, pid)
	}

	cfg.MinPeers = config.GlobalConfig.P2P.ConnectionManager.MaxNumPeers
	cfg.MaxPeers = cfg.MinPeers + peersHighWatermarkDelta
	cfg.GracePeriod = config.GlobalConfig.P2P.ConnectionManager.PeerGracePeriod
	cfg.PersistentPeers = persistentPeers

	return nil
}

// ConnGaterConfig describes a set of settings for a connection gater.
type ConnGaterConfig struct {
	BlockedPeers []net.IP
}

// NewConnGater constructs a new connection gater.
func NewConnGater(cfg *ConnGaterConfig) (*conngater.BasicConnectionGater, error) {
	// Set up a connection gater and block blacklisted peers.
	cg, err := conngater.NewBasicConnectionGater(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection gater: %w", err)
	}

	for _, ip := range cfg.BlockedPeers {
		if err = cg.BlockAddr(ip); err != nil {
			return nil, fmt.Errorf("connection gater failed to block IP (%s): %w", ip, err)
		}
	}
	return cg, nil
}

// NewConnGater constructs a new connection gater.
func (cfg *ConnGaterConfig) NewConnGater() (*conngater.BasicConnectionGater, error) {
	return NewConnGater(cfg)
}

// Load loads connection gater configuration.
func (cfg *ConnGaterConfig) Load() error {
	blockedPeers := make([]net.IP, 0)
	for _, blockedIP := range config.GlobalConfig.P2P.ConnectionGater.BlockedPeerIPs {
		parsedIP := net.ParseIP(blockedIP)
		if parsedIP == nil {
			return fmt.Errorf("malformed blocked IP: %s", blockedIP)
		}
		blockedPeers = append(blockedPeers, parsedIP)
	}

	cfg.BlockedPeers = blockedPeers

	return nil
}

// NewResourceManager constructs a new resource manager.
func NewResourceManager() (network.ResourceManager, error) {
	// Use the default resource manager for non-seed nodes.
	if config.GlobalConfig.Mode != config.ModeSeed {
		return nil, nil
	}

	// Tweak limits for seed nodes.
	//
	// Note: The connection manager will trim connections when the total number of inbound and
	// outbound connections exceeds the high watermark (default set to 130). Using autoscaling
	// and configuring the default limit to 128 seems to be a prudent choice.
	defaultLimits := rcmgr.DefaultLimits
	defaultLimits.SystemBaseLimit.ConnsInbound = 128
	defaultLimits.SystemBaseLimit.StreamsInbound = 128 * 16
	defaultLimits.SystemLimitIncrease.ConnsInbound = 128
	defaultLimits.SystemLimitIncrease.StreamsInbound = 128 * 16

	// Add limits around included libp2p protocols.
	libp2p.SetDefaultServiceLimits(&defaultLimits)

	// Scale limits.
	scaledLimits := defaultLimits.AutoScale()

	// The resource manager expects a limiter, se we create one from our limits.
	limiter := rcmgr.NewFixedLimiter(scaledLimits)

	// Initialize the resource manager.
	return rcmgr.NewResourceManager(limiter)
}
