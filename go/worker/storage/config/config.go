// Package config implements global configuration options.
package config

import (
	"fmt"
	"time"
)

// Config is the storage worker configuration structure.
type Config struct {
	// Storage backend.
	Backend string `yaml:"backend"`
	// Maximum in-memory cache size.
	MaxCacheSize string `yaml:"max_cache_size"`
	// Number of concurrent storage diff fetchers.
	FetcherCount uint `yaml:"fetcher_count"`

	// Enable storage RPC access for all nodes.
	PublicRPCEnabled bool `yaml:"public_rpc_enabled,omitempty"`
	// Disable initial storage sync from checkpoints.
	CheckpointSyncDisabled bool `yaml:"checkpoint_sync_disabled,omitempty"`

	// Storage checkpointer configuration.
	Checkpointer CheckpointerConfig `yaml:"checkpointer,omitempty"`
}

// CheckpointerConfig is the storage worker checkpointer configuration structure.
type CheckpointerConfig struct {
	// Enable the storage checkpointer.
	Enabled bool `yaml:"enabled"`
	// Storage checkpointer check interval.
	CheckInterval time.Duration `yaml:"check_interval"`
}

// Validate validates the configuration settings.
func (c *Config) Validate() error {
	if c.Backend != "badger" {
		return fmt.Errorf("unknown storage backend: %s", c.Backend)
	}

	return nil
}

// DefaultConfig returns the default configuration settings.
func DefaultConfig() Config {
	return Config{
		Backend:                "badger",
		MaxCacheSize:           "64mb",
		FetcherCount:           4,
		PublicRPCEnabled:       false,
		CheckpointSyncDisabled: false,
		Checkpointer: CheckpointerConfig{
			Enabled:       false,
			CheckInterval: 1 * time.Minute,
		},
	}
}
