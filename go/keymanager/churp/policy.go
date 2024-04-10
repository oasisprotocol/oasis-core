package churp

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

// PolicySGXSignatureContext is the context used to sign PolicySGX documents.
var PolicySGXSignatureContext = signature.NewContext("oasis-core/keymanager/churp: policy")

// PolicySGX represents an SGX access control policy used to authenticate
// key manager enclaves during handoffs.
type PolicySGX struct {
	Identity

	// Serial is the monotonically increasing policy serial number.
	Serial uint32 `json:"serial"`

	// MayShare is the vector of enclave identities from which a share can be
	// obtained during handouts.
	MayShare []sgx.EnclaveIdentity `json:"may_share"`

	// MayJoin is the vector of enclave identities that may form the new
	// committee in the next handoffs.
	MayJoin []sgx.EnclaveIdentity `json:"may_join"`
}

// SanityCheck verifies the validity of the policy.
func (p *PolicySGX) SanityCheck(prev *PolicySGX) error {
	switch prev {
	case nil:
		switch {
		case p.Serial != 0:
			return fmt.Errorf("SGX policy: sanity check failed: serial number must be 0 and not %d", p.Serial)
		}
	default:
		switch {
		case p.ID != prev.ID:
			return fmt.Errorf("SGX policy: sanity check failed: ID changed from %d to %d", prev.ID, p.ID)
		case p.RuntimeID != prev.RuntimeID:
			return fmt.Errorf("SGX policy: sanity check failed: runtime ID changed from %s to %s", prev.RuntimeID, p.RuntimeID)
		case p.Serial != prev.Serial+1:
			return fmt.Errorf("SGX policy: sanity check failed: serial number must be %d and not %d", prev.Serial+1, p.Serial)
		}
	}

	return nil
}

// SignedPolicySGX represents a signed SGX access control policy.
//
// The runtime extension will accept the policy only if all signatures are
// valid, and a sufficient number of trusted policy signers have signed it.
type SignedPolicySGX struct {
	// Policy is an SGX access control policy.
	Policy PolicySGX `json:"policy"`

	// Signatures is a vector of signatures.
	Signatures []signature.Signature `json:"signatures,omitempty"`
}

// SanityCheck verifies the validity of the policy and the signatures.
func (p *SignedPolicySGX) SanityCheck(prev *PolicySGX) error {
	if err := p.Policy.SanityCheck(prev); err != nil {
		return err
	}

	raw := cbor.Marshal(p.Policy)
	for _, sig := range p.Signatures {
		if !sig.PublicKey.IsValid() {
			return fmt.Errorf("SGX policy: sanity check failed: signature's public key %s is invalid", sig.PublicKey.String())
		}
		if !sig.Verify(PolicySGXSignatureContext, raw) {
			return fmt.Errorf("SGX policy: sanity check failed: policy signature from %s is invalid", sig.PublicKey.String())
		}
	}

	return nil
}

// Sign signs the policy with the given signer and appends the signatures.
func (p *SignedPolicySGX) Sign(signers []signature.Signer) error {
	if len(signers) == 0 {
		return nil
	}

	rawPolicy := cbor.Marshal(p.Policy)

	sigs := make([]signature.Signature, 0, len(signers))
	for _, signer := range signers {
		sig, err := signature.Sign(signer, PolicySGXSignatureContext, rawPolicy)
		if err != nil {
			return err
		}
		sigs = append(sigs, *sig)
	}

	p.Signatures = append(p.Signatures, sigs...)

	return nil
}
