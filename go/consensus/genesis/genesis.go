// Package genesis provides consensus config flags that should be part of the genesis state.
package genesis

import (
	"fmt"
	"time"

	tendermint "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
)

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

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	if g.Backend != tendermint.BackendName {
		return fmt.Errorf("consensus: sanity check failed: backend is invalid")
	}

	if g.Parameters.TimeoutCommit < 1*time.Millisecond && !g.Parameters.SkipTimeoutCommit {
		return fmt.Errorf("consensus: sanity check failed: timeout commit must be >= 1ms")
	}

	return nil
}
