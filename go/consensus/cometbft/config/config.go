// Package config implements global configuration options.
package config

import (
	"fmt"
	"time"
)

// Config is the CometBFT configuration structure.
type Config struct {
	// Node is a consensus validator.
	// This additional option exists because it is currently possible to
	// run a node that is simultaneously a validator and a compute node.
	Validator bool `yaml:"validator"`

	// CometBFT listen address.
	ListenAddress string `yaml:"listen_address"`
	// CometBFT address advertised to other nodes.
	ExternalAddress string `yaml:"external_address,omitempty"`

	// CometBFT P2P configuration.
	P2P P2PConfig `yaml:"p2p,omitempty"`

	// CometBFT nodes for which we act as sentry of the form pubkey@IP:port.
	SentryUpstreamAddresses []string `yaml:"sentry_upstream_addresses,omitempty"`

	// Minimum gas price for this validator.
	MinGasPrice uint64 `yaml:"min_gas_price,omitempty"`

	// Transaction submission configuration.
	Submission SubmissionConfig `yaml:"submission,omitempty"`

	// Epoch at which to force-shutdown the node (in epochs, zero disables shutdown).
	HaltEpoch uint64 `yaml:"halt_epoch,omitempty"`

	// Height at which to force-shutdown the node (in blocks, zero disables shutdown).
	HaltHeight uint64 `yaml:"halt_height,omitempty"`

	// Average amount of time to delay shutting down the node on upgrade.
	UpgradeStopDelay time.Duration `yaml:"upgrade_stop_delay,omitempty"`

	// ABCI state pruning configuration.
	Prune PruneConfig `yaml:"prune,omitempty"`

	// ABCI state checkpointer configuration.
	Checkpointer CheckpointerConfig `yaml:"checkpointer,omitempty"`

	// Consensus state sync configuration.
	StateSync StateSyncConfig `yaml:"state_sync,omitempty"`

	// LightClient contains light client configuration.
	LightClient LightClientConfig `yaml:"light_client,omitempty"`

	// Providers contains the CometBFT node addresses the stateless client
	// connects to in order to fetch consensus-related data.
	Providers []string `yaml:"providers,omitempty"`

	// Supplementary sanity checks configuration.
	SupplementarySanity SupplementarySanityConfig `yaml:"supplementary_sanity,omitempty"`

	// Enable CometBFT debug logs (very verbose).
	LogDebug bool `yaml:"log_debug,omitempty"`

	// Debug configuration options (do not use).
	Debug DebugConfig `yaml:"debug,omitempty"`
}

// P2PConfig is the CometBFT P2P configuration structure.
type P2PConfig struct {
	// Max number of inbound peers.
	MaxNumInboundPeers int `yaml:"max_num_inbound_peers"`
	// Max number of outbound peers (excluding persistent peers).
	MaxNumOutboundPeers int `yaml:"max_num_outbound_peers"`
	// Rate at which P2P packets can be sent (bytes/s).
	SendRate int64 `yaml:"send_rate"`
	// Rate at which P2P packets can be received (bytes/s).
	RecvRate int64 `yaml:"recv_rate"`

	// CometBFT persistent peer(s) of the form pubkey@IP:port.
	PersistentPeer []string `yaml:"persistent_peers"`
	// CometBFT unconditional peer(s) public keys.
	UnconditionalPeer []string `yaml:"unconditional_peers"`
	// Disable CometBFT's peer-exchange reactor.
	DisablePeerExchange bool `yaml:"disable_peer_exchange"`
	// CometBFT max timeout when redialing a persistent peer (default: unlimited).
	PersistentPeersMaxDialPeriod time.Duration `yaml:"persistent_peers_max_dial_period"`
}

// SubmissionConfig is the transaction submission configuration.
type SubmissionConfig struct {
	// Gas price used when submitting consensus transactions.
	GasPrice uint64 `yaml:"gas_price"`
	// Max transaction fee when submitting consensus transactions.
	MaxFee uint64 `yaml:"max_fee"`
}

const (
	// PruneStrategyNone is the identifier of the strategy that disables pruning.
	PruneStrategyNone = "none"
	// PruneStrategyKeepN is the identifier of the strategy that keeps the last N versions.
	PruneStrategyKeepN = "keep_n"
)

// PruneConfig is the CometBFT ABCI state pruning configuration structure.
type PruneConfig struct {
	// ABCI state pruning strategy.
	Strategy string `yaml:"strategy"`
	// ABCI state versions kept (when applicable).
	NumKept uint64 `yaml:"num_kept"`
	// ABCI state pruning interval.
	Interval time.Duration `yaml:"interval"`
}

// CheckpointerConfig is the CometBFT ABCI state pruning configuration structure.
type CheckpointerConfig struct {
	// Disable the ABCI state checkpointer.
	Disabled bool `yaml:"disabled"`
	// ABCI state checkpointer check interval.
	CheckInterval time.Duration `yaml:"check_interval"`
	// ParallelChunker specifies if the new parallel chunking algorithm is used.
	ParallelChunker bool `yaml:"parallel_chunker"`
}

// StateSyncConfig is the consensus state sync configuration structure.
type StateSyncConfig struct {
	// Enable consensus state sync.
	Enabled bool `yaml:"enabled,omitempty"`
}

// LightClientConfig is the consensus light client configuration structure.
type LightClientConfig struct {
	// Trust contains trust parameters required for a light client
	// to securely connect to the network.
	Trust TrustConfig `yaml:"trust,omitempty"`
}

// TrustConfig contains trust parameters required for a light client
// to securely connect to the network.
//
// This information should be obtained from a trusted source, such as
// a validator, a friend, a trusted peer, or a secure website.
type TrustConfig struct {
	// Period is the duration for which the trust remains valid.
	//
	// Should be significantly shorter than the unbonding period.
	// Specifically, the sum of the trust period, the time required
	// to verify headers, and the time needed to detect and penalize
	// misbehavior must be less than the unbonding period.
	Period time.Duration `yaml:"period,omitempty"`
	// Height is the height of a trusted consensus header.
	Height uint64 `yaml:"height,omitempty"`
	// Hash is the hash of a trusted consensus header.
	Hash string `yaml:"hash,omitempty"`
}

// SupplementarySanityConfig is the supplementary sanity configuration structure.
type SupplementarySanityConfig struct {
	// Enable supplementary sanity checks (slows down consensus).
	Enabled bool `yaml:"enabled"`
	// Supplementary sanity check interval (in blocks).
	Interval uint64 `yaml:"interval"`
}

// DebugConfig is the debug configuration structure.
type DebugConfig struct {
	// Allow non-routable addresses in P2P address book.
	P2PAddrBookLenient bool `yaml:"addr_book_lenient,omitempty"`
	// Allow multiple P2P connections from the same IP.
	P2PAllowDuplicateIP bool `yaml:"allow_duplicate_ip,omitempty"`

	// Enable automatic recovery from corrupted WAL during replay (UNSAFE).
	UnsafeReplayRecoverCorruptedWAL bool `yaml:"unsafe_replay_recover_corrupted_wal,omitempty"`

	// Disable populating seed node address book with genesis validators.
	DisableAddrBookFromGenesis bool `yaml:"disable_addr_book_from_genesis,omitempty"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	if c.P2P.MaxNumInboundPeers < 0 {
		return fmt.Errorf("p2p.max_num_inbound_peers must be >= 0")
	}
	if c.P2P.MaxNumOutboundPeers < 0 {
		return fmt.Errorf("p2p.max_num_outbound_peers must be >= 0")
	}

	if c.P2P.SendRate < 0 {
		return fmt.Errorf("p2p.send_rate must be >= 0")
	}
	if c.P2P.RecvRate < 0 {
		return fmt.Errorf("p2p.recv_rate must be >= 0")
	}

	if c.HaltHeight > 0 && c.HaltEpoch > 0 {
		return fmt.Errorf("only one of {halt_epoch, halt_height} can be set")
	}

	if c.StateSync.Enabled {
		if c.LightClient.Trust.Hash == "" {
			return fmt.Errorf("state sync requires light client to be configured")
		}
	}

	if c.LightClient.Trust.Hash != "" {
		if c.LightClient.Trust.Period == 0 {
			return fmt.Errorf("trust period must be greater than zero")
		}
		if c.LightClient.Trust.Height == 0 {
			return fmt.Errorf("trust height must be greater than zero")
		}
		if len(c.LightClient.Trust.Hash) != 64 {
			return fmt.Errorf("malformed trust hash")
		}
	}

	if c.SupplementarySanity.Enabled && c.SupplementarySanity.Interval < 1 {
		return fmt.Errorf("supplementary_sanity.interval must be >= 1")
	}
	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Validator:       false,
		ExternalAddress: "",
		ListenAddress:   "tcp://0.0.0.0:26656",
		P2P: P2PConfig{
			MaxNumInboundPeers:           100,
			MaxNumOutboundPeers:          20,
			SendRate:                     5120000,
			RecvRate:                     5120000,
			PersistentPeer:               []string{},
			UnconditionalPeer:            []string{},
			DisablePeerExchange:          false,
			PersistentPeersMaxDialPeriod: 0,
		},
		SentryUpstreamAddresses: []string{},
		MinGasPrice:             0,
		Submission: SubmissionConfig{
			GasPrice: 0,
			MaxFee:   10_000_000_000,
		},
		HaltEpoch:        0,
		HaltHeight:       0,
		UpgradeStopDelay: time.Minute,
		Prune: PruneConfig{
			Strategy: PruneStrategyNone,
			NumKept:  3600,
			Interval: 2 * time.Minute,
		},
		Checkpointer: CheckpointerConfig{
			Disabled:        false,
			CheckInterval:   time.Minute,
			ParallelChunker: false,
		},
		StateSync: StateSyncConfig{
			Enabled: false,
		},
		LightClient: LightClientConfig{
			Trust: TrustConfig{
				Period: 30 * 24 * time.Hour,
			},
		},
		SupplementarySanity: SupplementarySanityConfig{
			Enabled:  false,
			Interval: 10,
		},
		LogDebug: false,
		Debug: DebugConfig{
			P2PAddrBookLenient:              false,
			P2PAllowDuplicateIP:             false,
			UnsafeReplayRecoverCorruptedWAL: false,
			DisableAddrBookFromGenesis:      false,
		},
	}
}
