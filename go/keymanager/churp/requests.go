package churp

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

var (
	// ApplicationRequestSignatureContext is the signature context used to sign
	// application requests with runtime signing key (RAK).
	ApplicationRequestSignatureContext = signature.NewContext("oasis-core/keymanager/churp: application request")

	// ConfirmationRequestSignatureContext is the signature context used to sign
	// confirmation requests with runtime signing key (RAK).
	ConfirmationRequestSignatureContext = signature.NewContext("oasis-core/keymanager/churp: confirmation request")
)

// CreateRequest contains the initial configuration.
type CreateRequest struct {
	Identity

	// SuiteID is the identifier of a cipher suite used for verifiable secret
	// sharing and key derivation.
	SuiteID uint8 `json:"suite_id,omitempty"`

	// Threshold is the minimum number of distinct shares required
	// to reconstruct a key.
	Threshold uint8 `json:"threshold,omitempty"`

	// ExtraShares represents the minimum number of shares that can be lost
	// to render the secret unrecoverable.
	ExtraShares uint8 `json:"extra_shares,omitempty"`

	// HandoffInterval is the time interval in epochs between handoffs.
	//
	// A zero value disables handoffs.
	HandoffInterval beacon.EpochTime `json:"handoff_interval,omitempty"`

	// Policy is a signed SGX access control policy.
	Policy SignedPolicySGX `json:"policy,omitempty"`
}

// ValidateBasic performs basic config validity checks.
func (c *CreateRequest) ValidateBasic() error {
	if c.SuiteID > 0 {
		return fmt.Errorf("unsupported suite, ID %d", c.SuiteID)
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

	// ExtraShares represents the minimum number of shares that can be lost
	// to render the secret unrecoverable.
	ExtraShares *uint8 `json:"extra_shares,omitempty"`

	// HandoffInterval is the time interval in epochs between handoffs.
	//
	// Zero value disables handoffs.
	HandoffInterval *beacon.EpochTime `json:"handoff_interval,omitempty"`

	// Policy is a signed SGX access control policy.
	Policy *SignedPolicySGX `json:"policy,omitempty"`
}

// ValidateBasic performs basic config validity checks.
func (c *UpdateRequest) ValidateBasic() error {
	if c.ExtraShares == nil && c.HandoffInterval == nil && c.Policy == nil {
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

	// Epoch is the epoch of the handoff for which the node would like
	// to register.
	Epoch beacon.EpochTime `json:"epoch"`

	// Checksum is the hash of the verification matrix.
	Checksum hash.Hash `json:"checksum"`
}

// SignedApplicationRequest is an application request signed by the key manager
// enclave using its runtime attestation key (RAK).
type SignedApplicationRequest struct {
	Application ApplicationRequest `json:"application"`

	// Signature is the RAK signature of the application request.
	Signature signature.RawSignature `json:"signature"`
}

// VerifyRAK verifies the runtime attestation key (RAK) signature.
func (r *SignedApplicationRequest) VerifyRAK(rak *signature.PublicKey) error {
	if !rak.Verify(ApplicationRequestSignatureContext, cbor.Marshal(r.Application), r.Signature[:]) {
		return fmt.Errorf("RAK signature verification failed")
	}
	return nil
}

// ConfirmationRequest confirms that the node successfully completed
// the handoff.
type ConfirmationRequest struct {
	Identity

	// Epoch is the epoch of the handoff for which the node reconstructed
	// the share.
	Epoch beacon.EpochTime `json:"epoch"`

	// Checksum is the hash of the verification matrix.
	Checksum hash.Hash `json:"checksum"`
}

// SignedConfirmationRequest is a confirmation request signed by the key manager
// enclave using its runtime attestation key (RAK).
type SignedConfirmationRequest struct {
	Confirmation ConfirmationRequest `json:"confirmation"`

	// Signature is the RAK signature of the confirmation request.
	Signature signature.RawSignature `json:"signature"`
}

// VerifyRAK verifies the runtime attestation key (RAK) signature.
func (r *SignedConfirmationRequest) VerifyRAK(rak *signature.PublicKey) error {
	if !rak.Verify(ConfirmationRequestSignatureContext, cbor.Marshal(r.Confirmation), r.Signature[:]) {
		return fmt.Errorf("RAK signature verification failed")
	}
	return nil
}
