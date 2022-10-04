package api

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("beacon: sanity check failed: %w", err)
	}

	if g.Base == EpochInvalid {
		return fmt.Errorf("beacon: sanity check failed: starting epoch is invalid")
	}

	return nil
}

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	switch p.Backend {
	case BackendInsecure:
		params := p.InsecureParameters
		if params == nil {
			return fmt.Errorf("insecure backend not configured")
		}

		if params.Interval <= 0 && !p.DebugMockBackend {
			return fmt.Errorf("epoch interval must be > 0")
		}
	case BackendVRF:
		params := p.VRFParameters
		if params == nil {
			return fmt.Errorf("VRF backend not configured")
		}

		if params.AlphaHighQualityThreshold == 0 {
			return fmt.Errorf("alpha threshold must be > 0")
		}
		if params.Interval <= 0 {
			return fmt.Errorf("epoch interval must be > 0")
		}
		if params.ProofSubmissionDelay <= 0 {
			return fmt.Errorf("submission delay must be > 0")
		}
		if params.ProofSubmissionDelay >= params.Interval {
			return fmt.Errorf("submission delay must be < epoch interval")
		}
	default:
		return fmt.Errorf("unknown backend: '%s'", p.Backend)
	}

	unsafeFlags := p.DebugMockBackend
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("one or more unsafe debug flags set")
	}

	return nil
}
