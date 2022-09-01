package node

import "github.com/oasisprotocol/oasis-core/go/common/sgx/quote"

// TEEFeatures are the supported TEE features as advertised by the consensus layer.
type TEEFeatures struct {
	// SGX contains the supported TEE features for Intel SGX.
	SGX TEEFeaturesSGX `json:"sgx"`

	// FreshnessProofs is a feature flag specifying whether ProveFreshness transactions are
	// supported and processed, or ignored and handled as non-existing transactions.
	FreshnessProofs bool `json:"freshness_proofs"`
}

// TEEFeaturesSGX are the supported Intel SGX-specific TEE features.
type TEEFeaturesSGX struct {
	// PCS is a feature flag specifying whether support for Platform Certification Service-based
	// remote attestation is supported for Intel SGX-based TEEs.
	PCS bool `json:"pcs"`

	// DefaultPolicy is the default quote policy.
	DefaultPolicy *quote.Policy `json:"default_policy,omitempty"`
}

// ApplyDefaultPolicy applies configured quote policy defaults to the given policy, returning the
// new policy with defaults applied.
//
// In case no quote policy defaults are configured returns the policy unchanged.
func (fs *TEEFeaturesSGX) ApplyDefaultPolicy(policy *quote.Policy) *quote.Policy {
	if fs.DefaultPolicy == nil {
		return policy
	}

	if policy == nil {
		policy = &quote.Policy{}
	}
	if policy.IAS == nil {
		policy.IAS = fs.DefaultPolicy.IAS
	}
	if policy.PCS == nil && fs.PCS {
		policy.PCS = fs.DefaultPolicy.PCS
	}
	return policy
}
