package p2p

import (
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	manet "github.com/multiformats/go-multiaddr/net"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/persistent"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/config"
	"github.com/oasisprotocol/oasis-core/go/worker/common/configparser"
)

// Config describes a set of P2P settings for a peer.
type Config struct {
	Addresses []multiaddr.Multiaddr

	HostConfig
	GossipSubConfig
	BootstrapDiscoveryConfig
}

// HostConfig describes a set of settings for a host.
type HostConfig struct {
	Signer signature.Signer

	UserAgent  string
	ListenAddr multiaddr.Multiaddr
	Port       uint16

	ConnManagerConfig
	ConnGaterConfig
}

// ConnManagerConfig describes a set of settings for a connection manager.
type ConnManagerConfig struct {
	MinPeers        int
	MaxPeers        int
	GracePeriod     time.Duration
	PersistentPeers []peer.ID
}

// ConnGaterConfig describes a set of settings for a connection gater.
type ConnGaterConfig struct {
	BlockedPeers []net.IP
}

// GossipSubConfig describes a set of settings for a gossip pubsub.
type GossipSubConfig struct {
	// XXX: Main config has int64, but here just int -- investigate.
	PeerOutboundQueueSize int
	ValidateQueueSize     int
	ValidateThrottle      int

	PersistentPeers []peer.AddrInfo
}

// Load loads a default P2P configuration.
func (cfg *Config) Load(yamlCfg *config.Config) error {
	rawAddresses, err := configparser.ParseAddressList(yamlCfg.Registration.Addresses)
	if err != nil {
		return fmt.Errorf("failed to parse address list: %w", err)
	}
	var addresses []multiaddr.Multiaddr
	for _, addr := range rawAddresses {
		var mAddr multiaddr.Multiaddr
		mAddr, err = manet.FromNetAddr(addr.ToTCPAddr())
		if err != nil {
			return fmt.Errorf("failed to convert address to multiaddress: %w", err)
		}
		addresses = append(addresses, mAddr)
	}

	var hostCfg HostConfig
	if err := hostCfg.Load(yamlCfg); err != nil {
		return fmt.Errorf("failed to load host config: %w", err)
	}

	var gossipSubCfg GossipSubConfig
	if err := gossipSubCfg.Load(yamlCfg); err != nil {
		return fmt.Errorf("failed to load gossipsub config: %w", err)
	}

	var bootstrapCfg BootstrapDiscoveryConfig
	if err := bootstrapCfg.Load(yamlCfg); err != nil {
		return fmt.Errorf("failed to load bootstrap config: %w", err)
	}

	cfg.Addresses = addresses
	cfg.HostConfig = hostCfg
	cfg.GossipSubConfig = gossipSubCfg
	cfg.BootstrapDiscoveryConfig = bootstrapCfg

	return nil
}

// Load loads host configuration.
func (cfg *HostConfig) Load(yamlCfg *config.Config) error {
	userAgent := fmt.Sprintf("oasis-core/%s", version.SoftwareVersion)

	port := yamlCfg.Port

	// Listen for connections on all interfaces.
	listenAddr, err := multiaddr.NewMultiaddr(
		fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
	)
	if err != nil {
		return fmt.Errorf("failed to create multiaddress: %w", err)
	}

	var cmCfg ConnManagerConfig
	if err = cmCfg.Load(&yamlCfg.ConnectionManager); err != nil {
		return fmt.Errorf("failed to load connection manager config: %w", err)
	}

	var cgCfg ConnGaterConfig
	if err = cgCfg.Load(yamlCfg.ConnectionGater.BlockedPeerIPs); err != nil {
		return fmt.Errorf("failed to load connection gater config: %w", err)
	}

	cfg.UserAgent = userAgent
	cfg.Port = port
	cfg.ListenAddr = listenAddr
	cfg.ConnManagerConfig = cmCfg
	cfg.ConnGaterConfig = cgCfg

	return nil
}

// Load loads connection manager configuration.
func (cfg *ConnManagerConfig) Load(yamlCfg *config.ConnectionManagerConfig) error {
	persistentPeersMap := make(map[core.PeerID]struct{})
	for _, pp := range yamlCfg.PersistentPeers {
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

	cfg.MinPeers = yamlCfg.MaxNumPeers
	cfg.MaxPeers = cfg.MinPeers + peersHighWatermarkDelta
	cfg.GracePeriod = yamlCfg.PeerGracePeriod
	cfg.PersistentPeers = persistentPeers

	return nil
}

// Load loads connection gater configuration.
func (cfg *ConnGaterConfig) Load(blocked []string) error {
	blockedPeers := make([]net.IP, 0)
	for _, blockedIP := range blocked {
		parsedIP := net.ParseIP(blockedIP)
		if parsedIP == nil {
			return fmt.Errorf("malformed blocked IP: %s", blockedIP)
		}
		blockedPeers = append(blockedPeers, parsedIP)
	}

	cfg.BlockedPeers = blockedPeers

	return nil
}

// Load loads gossipsub configuration.
func (cfg *GossipSubConfig) Load(yamlCfg *config.Config) error {
	persistentPeers, err := api.AddrInfosFromConsensusAddrs(yamlCfg.ConnectionManager.PersistentPeers)
	if err != nil {
		return fmt.Errorf("failed to convert persistent peers' addresses: %w", err)
	}

	cfg.PeerOutboundQueueSize = yamlCfg.Gossipsub.PeerOutboundQueueSize
	cfg.ValidateQueueSize = yamlCfg.Gossipsub.ValidateQueueSize
	cfg.ValidateThrottle = yamlCfg.Gossipsub.ValidateThrottle
	cfg.PersistentPeers = persistentPeers

	return nil
}

// BootstrapDiscoveryConfig describes a set of settings for a discovery.
type BootstrapDiscoveryConfig struct {
	Enable          bool
	Seeds           []peer.AddrInfo
	RetentionPeriod time.Duration
}

// Load loads bootstrap discovery configuration.
func (cfg *BootstrapDiscoveryConfig) Load(yamlCfg *config.Config) error {
	seeds, err := api.AddrInfosFromConsensusAddrs(yamlCfg.Seeds)
	if err != nil {
		return fmt.Errorf("failed to convert seeds' addresses: %w", err)
	}

	cfg.Seeds = seeds
	cfg.Enable = yamlCfg.Discovery.Bootstrap.Enable
	cfg.RetentionPeriod = yamlCfg.Discovery.Bootstrap.RetentionPeriod

	return nil
}

// SeedConfig describes a set of settings for a seed.
type SeedConfig struct {
	CommonStore *persistent.CommonStore

	HostConfig
	BootstrapDiscoveryConfig
}

// Load loads seed configuration.
func (cfg *SeedConfig) Load(yamlCfg *config.Config) error {
	var hostCfg HostConfig
	if err := hostCfg.Load(yamlCfg); err != nil {
		return fmt.Errorf("failed to load host config: %w", err)
	}

	var bootstrapCfg BootstrapDiscoveryConfig
	if err := bootstrapCfg.Load(yamlCfg); err != nil {
		return fmt.Errorf("failed to load bootstrap config: %w", err)
	}

	cfg.HostConfig = hostCfg
	cfg.BootstrapDiscoveryConfig = bootstrapCfg

	return nil
}
