package api

import (
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// SanityCheckBlocks examines the blocks table.
func SanityCheckBlocks(blocks map[common.Namespace]*block.Block) error {
	for _, blk := range blocks {
		hdr := blk.Header

		if hdr.Timestamp > block.Timestamp(time.Now().Unix()+61*60) {
			return fmt.Errorf("roothash: sanity check failed: block header timestamp is more than 1h1m in the future")
		}
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("roothash: sanity check failed: %w", err)
	}

	// Check blocks.
	for _, rtg := range g.RuntimeStates {
		if err := rtg.SanityCheck(true); err != nil {
			return err
		}
	}
	return nil
}

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	unsafeFlags := p.DebugDoNotSuspendRuntimes || p.DebugBypassStake
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("one or more unsafe debug flags set")
	}
	return nil
}

// SanityCheck performs a sanity check on the consensus parameter changes.
func (c *ConsensusParameterChanges) SanityCheck() error {
	if c.GasCosts == nil &&
		c.MaxRuntimeMessages == nil &&
		c.MaxInRuntimeMessages == nil &&
		c.MaxEvidenceAge == nil {
		return fmt.Errorf("consensus parameter changes should not be empty")
	}
	return nil
}
