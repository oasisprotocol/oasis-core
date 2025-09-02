package secrets

import (
	"fmt"
)

// SanityCheckStatuses examines the statuses table.
func SanityCheckStatuses(statuses []*Status) error {
	for _, status := range statuses {
		// Verify key manager runtime ID.
		if !status.ID.IsKeyManager() {
			return fmt.Errorf("keymanager: sanity check failed: key manager runtime ID %s is invalid", status.ID)
		}

		// Verify currently active key manager node IDs.
		for _, node := range status.Nodes {
			if !node.IsValid() {
				return fmt.Errorf("keymanager: sanity check failed: key manager node ID %s is invalid", node.String())
			}
		}

		// Verify SGX policy signatures if the policy exists.
		if status.Policy != nil {
			if err := SanityCheckSignedPolicySGX(nil, status.Policy); err != nil {
				return err
			}
		}
		if status.NextPolicy != nil {
			if err := SanityCheckSignedPolicySGX(status.Policy, status.NextPolicy); err != nil {
				return err
			}
		}
	}
	return nil
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	if err := g.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("keymanager: sanity check failed: %w", err)
	}

	return SanityCheckStatuses(g.Statuses)
}

// SanityCheck performs a sanity check on the consensus parameters.
func (p *ConsensusParameters) SanityCheck() error {
	return nil
}

// SanityCheck performs a sanity check on the consensus parameter changes.
func (c *ConsensusParameterChanges) SanityCheck() error {
	if c.GasCosts == nil {
		return fmt.Errorf("consensus parameter changes should not be empty")
	}
	return nil
}
