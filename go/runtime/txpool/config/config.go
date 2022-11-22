// Package config implements the txpool configuration options.
package config

import "time"

// Config is the runtime transaction pool configuration structure.
type Config struct {
	// Maximum size of the scheduling transaction pool.
	MaxPoolSize uint64 `yaml:"schedule_max_tx_pool_size"`
	// Maximum cache size of recently scheduled transactions to prevent re-scheduling.
	MaxLastSeenCacheSize uint64 `yaml:"schedule_tx_cache_size"`
	// Maximum check tx batch size.
	MaxCheckTxBatchSize uint64 `yaml:"check_tx_max_batch_size"`
	// Transaction recheck interval (in rounds).
	RecheckInterval uint64 `yaml:"recheck_interval"`
	// Republish interval.
	RepublishInterval time.Duration
}
