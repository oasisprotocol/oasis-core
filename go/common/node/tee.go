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

	// SignedAttestations is a feature flag specifying whether attestations need to include an
	// additional signature binding it to a specific node.
	SignedAttestations bool `json:"signed_attestations,omitempty"`

	// DefaultPolicy is the default quote policy.
	DefaultPolicy *quote.Policy `json:"default_policy,omitempty"`

	// DefaultMaxAttestationAge is the default maximum attestation age (in blocks).
	DefaultMaxAttestationAge uint64 `json:"max_attestation_age,omitempty"`
}

// ApplyDefaultConstraints applies configured SGX constraint defaults to the given structure.
func (fs *TEEFeaturesSGX) ApplyDefaultConstraints(sc *SGXConstraints) {
	// Default policy.
	if fs.DefaultPolicy != nil {
		if sc.Policy == nil {
			sc.Policy = &quote.Policy{}
		}
		if sc.Policy.IAS == nil {
			sc.Policy.IAS = fs.DefaultPolicy.IAS
		}
		if sc.Policy.PCS == nil && fs.PCS {
			sc.Policy.PCS = fs.DefaultPolicy.PCS
		}
	}

	// Default maximum attestation age.
	if sc.MaxAttestationAge == 0 {
		sc.MaxAttestationAge = fs.DefaultMaxAttestationAge
	}
}
