package churp

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
)

// CreateRequest contains the initial configuration.
type CreateRequest struct {
	Identity

	// GroupID is the identifier of a group used for verifiable secret sharing
	// and key derivation.
	GroupID uint8 `json:"group,omitempty"`

	// Threshold is the minimum number of distinct shares required
	// to reconstruct a key.
	Threshold uint8 `json:"threshold,omitempty"`

	// HandoffInterval is the time interval in epochs between handoffs.
	//
	// A zero value disables handoffs.
	HandoffInterval beacon.EpochTime `json:"handoff_interval,omitempty"`

	// Policy is a signed SGX access control policy.
	Policy SignedPolicySGX `json:"policy,omitempty"`
}

// ValidateBasic performs basic config validity checks.
func (c *CreateRequest) ValidateBasic() error {
	if c.Threshold < 1 {
		return fmt.Errorf("threshold must be at least 1, got %d", c.Threshold)
	}
	if c.GroupID > 0 {
		return fmt.Errorf("unsupported group, ID %d", c.GroupID)
	}
	if c.Policy.Policy.ID != c.ID {
		return fmt.Errorf("policy ID mismatch: got %d, expected %d", c.Policy.Policy.ID, c.ID)
	}
	if c.Policy.Policy.RuntimeID != c.RuntimeID {
		return fmt.Errorf("policy runtime ID mismatch: got %s, expected %s", c.Policy.Policy.RuntimeID, c.RuntimeID)
	}

	return nil
}

// UpdateRequest contains the updated configuration.
type UpdateRequest struct {
	Identity

	// HandoffInterval is the time interval in epochs between handoffs.
	//
	// Zero value disables handoffs.
	HandoffInterval *beacon.EpochTime `json:"handoff_interval,omitempty"`

	// Policy is a signed SGX access control policy.
	Policy *SignedPolicySGX `json:"policy,omitempty"`
}

// ValidateBasic performs basic config validity checks.
func (c *UpdateRequest) ValidateBasic() error {
	if c.HandoffInterval == nil && c.Policy == nil {
		return fmt.Errorf("update config should not be empty")
	}

	if c.Policy != nil {
		if c.Policy.Policy.ID != c.ID {
			return fmt.Errorf("policy ID mismatch: got %d, expected %d", c.Policy.Policy.ID, c.ID)
		}
		if c.Policy.Policy.RuntimeID != c.RuntimeID {
			return fmt.Errorf("policy runtime ID mismatch: got %s, expected %s", c.Policy.Policy.RuntimeID, c.RuntimeID)
		}
	}

	return nil
}
