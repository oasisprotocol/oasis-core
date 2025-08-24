// Package genesis provides consensus config flags that should be part of the genesis state.
package genesis

import (
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

// Genesis contains various consensus config flags that should be part of the genesis state.
type Genesis struct {
	Backend    string     `json:"backend"`
	Parameters Parameters `json:"params"`
}

// Parameters are the consensus parameters.
type Parameters struct {
	// TimeoutCommit specifies the duration to wait after committing a block
	// before starting a new height.
	TimeoutCommit time.Duration `json:"timeout_commit"`
	// SkipTimeoutCommit determines whether to proceed immediately once all
	// precommits are received.
	SkipTimeoutCommit bool `json:"skip_timeout_commit"`
	// EmptyBlockInterval defines the time interval between empty blocks.
	EmptyBlockInterval time.Duration `json:"empty_block_interval"`

	MaxTxSize       uint64          `json:"max_tx_size"`
	MaxBlockSize    uint64          `json:"max_block_size"`
	MaxBlockGas     transaction.Gas `json:"max_block_gas"`
	MaxEvidenceSize uint64          `json:"max_evidence_size"`

	// MinGasPrice is the minimum gas price.
	MinGasPrice uint64 `json:"min_gas_price,omitempty"`

	// StateCheckpointInterval is the expected state checkpoint interval (in blocks).
	StateCheckpointInterval uint64 `json:"state_checkpoint_interval"`
	// StateCheckpointNumKept is the expected minimum number of state checkpoints to keep.
	StateCheckpointNumKept uint64 `json:"state_checkpoint_num_kept,omitempty"`
	// StateCheckpointChunkSize is the chunk size parameter for checkpoint creation.
	StateCheckpointChunkSize uint64 `json:"state_checkpoint_chunk_size,omitempty"`

	// GasCosts are the base transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// PublicKeyBlacklist is the network-wide public key blacklist.
	PublicKeyBlacklist []signature.PublicKey `json:"public_key_blacklist,omitempty"`

	// FeatureVersion represents the latest consensus-breaking software version
	// that follows calendar versioning (yy.minor[.micro]).
	FeatureVersion *version.Version `json:"feature_version,omitempty"`
}

// IsFeatureVersion returns true iff the consensus feature version is high
// enough for the feature to be enabled.
func (p *Parameters) IsFeatureVersion(minVersion version.Version) bool {
	if p.FeatureVersion == nil {
		return false
	}

	return p.FeatureVersion.ToU64() >= minVersion.ToU64()
}

const (
	// GasOpTxByte is the gas operation identifier for costing each transaction byte.
	GasOpTxByte transaction.Op = "tx_byte"
)

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	params := g.Parameters

	if params.TimeoutCommit < 1*time.Millisecond && !params.SkipTimeoutCommit {
		return fmt.Errorf("consensus: sanity check failed: timeout commit must be >= 1ms")
	}

	if params.StateCheckpointInterval > 0 && !flags.DebugDontBlameOasis() {
		if params.StateCheckpointInterval < 1000 {
			return fmt.Errorf("consensus: sanity check failed: state checkpoint interval must be >= 1000")
		}

		if params.StateCheckpointNumKept == 0 {
			return fmt.Errorf("consensus: sanity check failed: number of kept state checkpoints must be > 0")
		}

		if params.StateCheckpointChunkSize < 1024*1024 {
			return fmt.Errorf("consensus: sanity check failed: state checkpoint chunk size must be >= 1 MiB")
		}
	}

	// Check for duplicate entries in the pk blacklist.
	m := make(map[signature.PublicKey]bool)
	for _, v := range params.PublicKeyBlacklist {
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
