package p2p

import (
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	rcmgr "github.com/libp2p/go-libp2p/p2p/host/resource-manager"
	"github.com/libp2p/go-libp2p/p2p/net/conngater"
	"github.com/libp2p/go-libp2p/p2p/net/connmgr"

	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
)

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
