package config

import (
	"fmt"
	"net"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"

	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

const (
	// peersHighWatermarkDelta specifies how many peers after the maximum peer count is reached we
	// ask the connection manager to start pruning peers.
	peersHighWatermarkDelta = 30
)

// Load loads P2P configuration.
func (c *Config) ToP2PConfig() (*p2p.Config, error) {
	var cfg p2p.Config
	rawAddresses, err := configparser.ParseAddressList(c.P2P.Registration.Addresses)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address list: %w", err)
	}
	var addresses []multiaddr.Multiaddr
	for _, addr := range rawAddresses {
		var mAddr multiaddr.Multiaddr
		mAddr, err = manet.FromNetAddr(addr.ToTCPAddr())
		if err != nil {
			return nil, fmt.Errorf("failed to convert address to multiaddress: %w", err)
		}
		addresses = append(addresses, mAddr)
	}

	hostCfg, err := c.hostConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create host config: %w", err)
	}

	gossipSubCfg, err := c.gossipSubConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create gossipsub config: %w", err)
	}

	bootstrapCfg, err := c.bootstrapDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap config: %w", err)
	}

	cfg.Addresses = addresses
	cfg.HostConfig = *hostCfg
	cfg.GossipSubConfig = *gossipSubCfg
	cfg.BootstrapDiscoveryConfig = *bootstrapCfg

	return &cfg, nil
}

func (c *Config) hostConfig() (*p2p.HostConfig, error) {
	var cfg p2p.HostConfig

	userAgent := fmt.Sprintf("oasis-core/%s", version.SoftwareVersion)

	// Listen for connections on all interfaces.
	listenAddr, err := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", c.P2P.Port),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create multiaddress: %w", err)
	}

	cmCfg, err := c.connManagerConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create connection manager config: %w", err)
	}

	cgCfg, err := c.connGaterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create connection gater config: %w", err)
	}

	cfg.UserAgent = userAgent
	cfg.Port = c.P2P.Port
	cfg.ListenAddr = listenAddr
	cfg.ConnManagerConfig = *cmCfg
	cfg.ConnGaterConfig = *cgCfg
	cfg.IsSeed = c.Mode == ModeSeed

	return &cfg, nil
}

func (c *Config) gossipSubConfig() (*p2p.GossipSubConfig, error) {
	var cfg p2p.GossipSubConfig
	persistentPeers, err := api.AddrInfosFromConsensusAddrs(GlobalConfig.P2P.ConnectionManager.PersistentPeers)
	if err != nil {
		return nil, fmt.Errorf("failed to convert persistent peers' addresses: %w", err)
	}

	cfg.PeerOutboundQueueSize = c.P2P.Gossipsub.PeerOutboundQueueSize
	cfg.ValidateQueueSize = c.P2P.Gossipsub.ValidateQueueSize
	cfg.ValidateThrottle = c.P2P.Gossipsub.ValidateThrottle
	cfg.PersistentPeers = persistentPeers
	cfg.ValidateConcurrency = c.P2P.Gossipsub.ValidateConcurrency

	return &cfg, nil

}

func (c *Config) bootstrapDiscovery() (*p2p.BootstrapDiscoveryConfig, error) {
	var cfg p2p.BootstrapDiscoveryConfig
	seeds, err := api.AddrInfosFromConsensusAddrs(c.P2P.Seeds)
	if err != nil {
		return nil, fmt.Errorf("failed to convert seeds' addresses: %w", err)
	}

	cfg.Seeds = seeds
	cfg.Enable = c.P2P.Discovery.Bootstrap.Enable
	cfg.RetentionPeriod = c.P2P.Discovery.Bootstrap.RetentionPeriod

	return &cfg, nil
}

func (c *Config) connManagerConfig() (*p2p.ConnManagerConfig, error) {
	var cfg p2p.ConnManagerConfig
	persistentPeersMap := make(map[core.PeerID]struct{})
	for _, pp := range c.P2P.ConnectionManager.PersistentPeers {
		var addr node.ConsensusAddress
		if err := addr.UnmarshalText([]byte(pp)); err != nil {
			return nil, fmt.Errorf("malformed address (expected pubkey@IP:port): %w", err)
		}

		pid, err := api.PublicKeyToPeerID(addr.ID)
		if err != nil {
			return nil, fmt.Errorf("invalid public key (%s): %w", addr.ID, err)
		}

		persistentPeersMap[pid] = struct{}{}
	}

	persistentPeers := make([]peer.ID, 0)
	for pid := range persistentPeersMap {
		persistentPeers = append(persistentPeers, pid)
	}

	cfg.MinPeers = c.P2P.ConnectionManager.MaxNumPeers
	cfg.MaxPeers = cfg.MinPeers + peersHighWatermarkDelta
	cfg.GracePeriod = c.P2P.ConnectionManager.PeerGracePeriod
	cfg.PersistentPeers = persistentPeers

	return &cfg, nil
}

func (c *Config) connGaterConfig() (*p2p.ConnGaterConfig, error) {
	var cfg p2p.ConnGaterConfig
	blockedPeers := make([]net.IP, 0)
	for _, blockedIP := range c.P2P.ConnectionGater.BlockedPeerIPs {
		parsedIP := net.ParseIP(blockedIP)
		if parsedIP == nil {
			return nil, fmt.Errorf("malformed blocked IP: %s", blockedIP)
		}
		blockedPeers = append(blockedPeers, parsedIP)
	}

	cfg.BlockedPeers = blockedPeers

	return &cfg, nil
}

func (c *Config) ToSeedConfig() (*p2p.SeedConfig, error) {
	var cfg p2p.SeedConfig

	hostCfg, err := c.hostConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to create host config: %w", err)
	}

	bootstrapCfg, err := c.bootstrapDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap config: %w", err)
	}

	cfg.HostConfig = hostCfg
	cfg.BootstrapDiscoveryConfig = bootstrapCfg

	return &cfg, nil
}
