package churp

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// ApplicationRequestSignatureContext is the signature context used to sign
// application requests with runtime signing key (RAK).
var ApplicationRequestSignatureContext = signature.NewContext("oasis-core/keymanager/churp: application request")

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

// ApplicationRequest contains node's application to form a new committee.
type ApplicationRequest struct {
	// Identity of the CHRUP scheme.
	Identity

	// Round is the round for which the node would like to register.
	Round uint64 `json:"round,omitempty"`

	// Checksum is the hash of the verification matrix.
	Checksum hash.Hash `json:"checksum,omitempty"`
}

// SignedApplicationRequest is an application request signed by the key manager
// enclave using its runtime attestation key (RAK).
type SignedApplicationRequest struct {
	Application ApplicationRequest `json:"application,omitempty"`

	// Signature is the RAK signature of the application request.
	Signature signature.RawSignature `json:"signature,omitempty"`
}

// VerifyRAK verifies the runtime attestation key (RAK) signature.
func (r *SignedApplicationRequest) VerifyRAK(rak *signature.PublicKey) error {
	if !rak.Verify(ApplicationRequestSignatureContext, cbor.Marshal(r.Application), r.Signature[:]) {
		return fmt.Errorf("RAK signature verification failed")
	}
	return nil
}
