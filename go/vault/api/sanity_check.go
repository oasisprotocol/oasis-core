// Package api implements the vault backend API.
package api

import (
	"fmt"
)

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	if !p.Enabled {
		return nil
	}
	if p.MaxAuthorityAddresses == 0 {
		return fmt.Errorf("maximum number of authority addresses should be greater than zero")
	}
	return nil
}

// SanityCheck performs a sanity check on the consensus parameter changes.
func (c *ConsensusParameterChanges) SanityCheck() error {
	if c.MaxAuthorityAddresses == nil && c.GasCosts == nil {
		return fmt.Errorf("consensus parameter changes should not be empty")
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	if g == nil {
		return nil
	}
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("vault: sanity check failed: %w", err)
	}
	return nil
}
