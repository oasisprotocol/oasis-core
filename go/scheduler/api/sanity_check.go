package api

import (
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
)

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(stakingTotalSupply *quantity.Quantity) error {
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("scheduler: sanity check failed: %w", err)
	}

	if !g.Parameters.DebugBypassStake {
		supplyPower, err := VotingPowerFromStake(stakingTotalSupply)
		if err != nil {
			return fmt.Errorf("scheduler: sanity check failed: total supply would break voting power computation: %w", err)
		}
		// I've been advised not to import implementation details.
		// Instead, here's our own number that satisfies all current implementations' limits.
		maxTotalVotingPower := int64(math.MaxInt64) / 8
		if supplyPower > maxTotalVotingPower {
			return fmt.Errorf("init chain: total supply power %d exceeds Tendermint voting power limit %d", supplyPower, maxTotalVotingPower)
		}
	}

	return nil
}

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	unsafeFlags := p.DebugBypassStake || p.DebugAllowWeakAlpha || p.DebugForceElect != nil
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("one or more unsafe debug flags set")
	}
	return nil
}

// SanityCheck performs a sanity check on the consensus parameter changes.
func (c *ConsensusParameterChanges) SanityCheck() error {
	if c.MinValidators == nil &&
		c.MaxValidators == nil {
		return fmt.Errorf("consensus parameter changes should not be empty")
	}
	return nil
}
