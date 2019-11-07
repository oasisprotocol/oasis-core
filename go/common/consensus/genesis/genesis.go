// Package genesis provides consensus config flags that should be part of the genesis state.
package genesis

import "time"

// Genesis contains various consensus config flags that should be part of the genesis state.
type Genesis struct {
	Backend            string        `json:"backend"`
	TimeoutCommit      time.Duration `json:"timeout_commit"`
	SkipTimeoutCommit  bool          `json:"skip_timeout_commit"`
	EmptyBlockInterval time.Duration `json:"empty_block_interval"`
	MaxTxSize          uint          `json:"max_tx_size"`
}
