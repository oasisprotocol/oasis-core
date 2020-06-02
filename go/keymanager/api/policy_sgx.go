package api

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

// PolicySGXSignatureContext is the context used to sign PolicySGX documents.
var PolicySGXSignatureContext = signature.NewContext("oasis-core/keymanager: policy")

// PolicySGX is a key manager access control policy for the replicated
// SGX key manager.
type PolicySGX struct {
	// Serial is the monotonically increasing policy serial number.
	Serial uint32 `json:"serial"`

	// ID is the runtime ID that this policy is valid for.
	ID common.Namespace `json:"id"`

	// Enclaves is the per-key manager enclave ID access control policy.
	Enclaves map[sgx.EnclaveIdentity]*EnclavePolicySGX `json:"enclaves"`
}

// EnclavePolicySGX is the per-SGX key manager enclave ID access control policy.
type EnclavePolicySGX struct {
	// MayQuery is the map of runtime IDs to the vector of enclave IDs that
	// may query private key material.
	//
	// TODO: This could be made more sophisticated and seggregate based on
	// contract ID as well, but for now punt on the added complexity.
	MayQuery map[common.Namespace][]sgx.EnclaveIdentity `json:"may_query"`

	// MayReplicate is the vector of enclave IDs that may retrieve the master
	// secret (Note: Each enclave ID may always implicitly replicate from other
	// instances of itself).
	MayReplicate []sgx.EnclaveIdentity `json:"may_replicate"`
}

// SignedPolicySGX is a signed SGX key manager access control policy.
type SignedPolicySGX struct {
	Policy PolicySGX `json:"policy"`

	Signatures []signature.Signature `json:"signatures"`
}

// SanityCheckSignedPolicySGX verifies a SignedPolicySGX.
func SanityCheckSignedPolicySGX(currentSigPol, newSigPol *SignedPolicySGX) error {
	newRawPol := cbor.Marshal(newSigPol.Policy)
	for _, sig := range newSigPol.Signatures {
		if !sig.PublicKey.IsValid() {
			return fmt.Errorf("keymanager: sanity check failed: SGX policy signature's public key %s is invalid", sig.PublicKey.String())
		}
		if !sig.Verify(PolicySGXSignatureContext, newRawPol) {
			return fmt.Errorf("keymanager: sanity check failed: SGX policy signature from %s is invalid", sig.PublicKey.String())
		}
	}

	// If a prior version of the policy is not provided, then there is nothing
	// more to check.  Even with a prior version of the document, since policy
	// updates can happen independently of a new version of the enclave, it's
	// basically impossible to generically validate the Enclaves portion.
	if currentSigPol == nil {
		return nil
	}

	currentPol, newPol := currentSigPol.Policy, newSigPol.Policy
	if !newPol.ID.Equal(&currentPol.ID) {
		return fmt.Errorf("keymanager: sanity check failed: SGX policy runtime ID changed from %s to %s", currentPol.ID, newPol.ID)
	}

	if currentPol.Serial >= newPol.Serial {
		return fmt.Errorf("keymanager: sanity check failed: SGX policy serial number did not increase")
	}

	return nil
}
