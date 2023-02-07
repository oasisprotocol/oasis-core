// Package config implements global configuration options.
package config

import (
	"fmt"
	"time"
)

// Config is the P2P configuration structure.
type Config struct {
	// Port to use for incoming P2P connections.
	Port uint16 `yaml:"port"`

	// Seed node(s) of the form pubkey@IP:port.
	Seeds []string `yaml:"seeds,omitempty"`

	Discovery         DiscoveryConfig         `yaml:"discovery,omitempty"`
	Registration      RegistrationConfig      `yaml:"registration,omitempty"`
	Gossipsub         GossipsubConfig         `yaml:"gossipsub,omitempty"`
	PeerManager       PeerManagerConfig       `yaml:"peer_manager,omitempty"`
	ConnectionManager ConnectionManagerConfig `yaml:"connection_manager,omitempty"`
	ConnectionGater   ConnectionGaterConfig   `yaml:"connection_gater,omitempty"`
}

// DiscoveryConfig is the P2P discovery configuration structure.
type DiscoveryConfig struct {
	Bootstrap BootstrapConfig `yaml:"bootstrap"`
}

// BootstrapConfig is the P2P discovery bootstrap configuration structure.
type BootstrapConfig struct {
	// Enable bootstrap discovery protocol.
	Enable bool `yaml:"enable"`
	// Retention period for peers discovered through seed nodes.
	RetentionPeriod time.Duration `yaml:"retention_period"`
}

// RegistrationConfig is the P2P registration configuration structure.
type RegistrationConfig struct {
	// Address/port(s) to use for P2P connections when registering this node
	// (if not set, all non-loopback local interfaces will be used).
	Addresses []string `yaml:"addresses"`
}

// GossipsubConfig is the P2P gossipsub configuration structure.
type GossipsubConfig struct {
	// Set libp2p gossipsub buffer size for outbound messages.
	PeerOutboundQueueSize int `yaml:"peer_outbound_queue_size"`
	// Set libp2p gossipsub buffer size of the validate queue.
	ValidateQueueSize int `yaml:"validate_queue_size"`
	// Set libp2p gossipsub per topic validator concurrency limit.
	ValidateConcurrency int `yaml:"validate_concurrency"`
	// Set libp2p gossipsub validator concurrency limit.
	// Note: This is a global (across all topics) validator concurrency limit.
	ValidateThrottle int `yaml:"validate_throttle"`
}

// PeerManagerConfig is the P2P peer manager configuration structure.
type PeerManagerConfig struct {
	// Set the low water mark at which the peer manager will try to reconnect to peers.
	ConnectednessLowWater float64 `yaml:"connectedness_low_water"`
}

// ConnectionManagerConfig is the P2P connection manager configuration structure.
type ConnectionManagerConfig struct {
	// Set maximum number of P2P peers.
	MaxNumPeers int `yaml:"max_num_peers"`
	// Time duration for new peer connections to be immune from pruning.
	PeerGracePeriod time.Duration `yaml:"peer_grace_period"`
	// List of persistent peer node addresses in format P2Ppubkey@IP:port.
	PersistentPeers []string `yaml:"persistent_peers,omitempty"`
}

// ConnectionGaterConfig is the P2P connection gater configuration structure.
type ConnectionGaterConfig struct {
	// List of blocked peer IPs.
	BlockedPeerIPs []string `yaml:"blocked_peers"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	if c.ConnectionManager.MaxNumPeers < 0 {
		return fmt.Errorf("connection_manager.max_num_peers must be >= 0")
	}

	if c.Gossipsub.PeerOutboundQueueSize < 0 {
		return fmt.Errorf("gossipsub.peer_outbound_queue_size must be >= 0")
	}
	if c.Gossipsub.ValidateQueueSize < 0 {
		return fmt.Errorf("gossipsub.validate_queue_size must be >= 0")
	}
	if c.Gossipsub.ValidateConcurrency < 0 {
		return fmt.Errorf("gossipsub.validate_concurrency must be >= 0")
	}
	if c.Gossipsub.ValidateThrottle < 0 {
		return fmt.Errorf("gossipsub.validate_throttle must be >= 0")
	}

	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Port:  9200,
		Seeds: []string{},
		Discovery: DiscoveryConfig{
			BootstrapConfig{
				Enable:          true,
				RetentionPeriod: 1 * time.Hour,
			},
		},
		Registration: RegistrationConfig{
			Addresses: []string{},
		},
		Gossipsub: GossipsubConfig{
			PeerOutboundQueueSize: 32,
			ValidateQueueSize:     32,
			ValidateConcurrency:   1024,
			ValidateThrottle:      8192,
		},
		PeerManager: PeerManagerConfig{
			ConnectednessLowWater: 0.2,
		},
		ConnectionManager: ConnectionManagerConfig{
			MaxNumPeers:     100,
			PeerGracePeriod: 20 * time.Second,
			PersistentPeers: []string{},
		},
		ConnectionGater: ConnectionGaterConfig{
			BlockedPeerIPs: []string{},
		},
	}
}
