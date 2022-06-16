package node

// TEEFeatures are the supported TEE features as advertised by the consensus layer.
type TEEFeatures struct {
	// SGX contains the supported TEE features for Intel SGX.
	SGX TEEFeaturesSGX `json:"sgx"`
}

// TEEFeaturesSGX are the supported Intel SGX-specific TEE features.
type TEEFeaturesSGX struct {
	// PCS is a feature flag specifying whether support for Platform Certification Service-based
	// remote attestation is supported for Intel SGX-based TEEs.
	PCS bool `json:"pcs"`
}
