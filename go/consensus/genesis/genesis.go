// Package genesis provides consensus config flags that should be part of the genesis state.
package genesis

import (
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
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

	MaxTxSize            uint64          `json:"max_tx_size"`
	MaxBlockSize         uint64          `json:"max_block_size"`
	MaxBlockGas          transaction.Gas `json:"max_block_gas"`
	MaxEvidenceAgeBlocks uint64          `json:"max_evidence_age_blocks"`
	MaxEvidenceAgeTime   time.Duration   `json:"max_evidence_age_time"`

	// GasCosts are the base transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// PublicKeyBlacklist is the network-wide public key blacklist.
	PublicKeyBlacklist []signature.PublicKey `json:"public_key_blacklist,omitempty"`
}

const (
	// GasOpTxByte is the gas operation identifier for costing each transaction byte.
	GasOpTxByte transaction.Op = "tx_byte"
)

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	if g.Parameters.TimeoutCommit < 1*time.Millisecond && !g.Parameters.SkipTimeoutCommit {
		return fmt.Errorf("consensus: sanity check failed: timeout commit must be >= 1ms")
	}

	// Check for duplicate entries in the pk blacklist.
	m := make(map[signature.PublicKey]bool)
	for _, v := range g.Parameters.PublicKeyBlacklist {
		if m[v] {
			return fmt.Errorf("consensus: sanity check failed: redundant blacklisted public key: '%s'", v)
		}
		if v.IsBlacklisted() {
			return fmt.Errorf("consensus: sanity check failed: public key already in blacklist: '%s'", v)
		}
		m[v] = true
	}

	return nil
}
