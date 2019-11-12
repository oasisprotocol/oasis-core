// Package genesis provides consensus config flags that should be part of the genesis state.
package genesis

import "time"

// Genesis contains various consensus config flags that should be part of the genesis state.
type Genesis struct {
	Backend    string     `json:"backend"`
	Parameters Parameters `json:"params"`
}

// Parameters are the consensus parameters.
type Parameters struct {
	TimeoutCommit      time.Duration `json:"timeout_commit"`
	SkipTimeoutCommit  bool          `json:"skip_timeout_commit"`
	EmptyBlockInterval time.Duration `json:"empty_block_interval"`

	MaxTxSize      uint64 `json:"max_tx_size"`
	MaxBlockSize   uint64 `json:"max_block_size"`
	MaxBlockGas    uint64 `json:"max_block_gas"`
	MaxEvidenceAge uint64 `json:"max_evidence_age"`
}
