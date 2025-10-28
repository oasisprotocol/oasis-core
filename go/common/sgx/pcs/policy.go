package pcs

import (
	"fmt"
)

// QuotePolicy is the quote validity policy.
type QuotePolicy struct {
	// Disabled specifies whether PCS quotes are disabled and will always be rejected.
	Disabled bool `json:"disabled,omitempty" yaml:"disabled,omitempty"`

	// TCBValidityPeriod is the validity (in days) of the TCB collateral.
	TCBValidityPeriod uint16 `json:"tcb_validity_period" yaml:"tcb_validity_period"`

	// MinTCBEvaluationDataNumber is the minimum TCB evaluation data number that is considered to be
	// valid. TCB bundles containing smaller values will be invalid.
	MinTCBEvaluationDataNumber uint32 `json:"min_tcb_evaluation_data_number" yaml:"min_tcb_evaluation_data_number"`

	// FMSPCWhitelist is a list of hexadecimal encoded FMSPCs specifying which processor
	// packages and platform instances are allowed.
	FMSPCWhitelist []string `json:"fmspc_whitelist,omitempty" yaml:"fmspc_whitelist,omitempty"`

	// FMSPCBlacklist is a list of hexadecimal encoded FMSPCs specifying which processor
	// packages and platform instances are blocked.
	FMSPCBlacklist []string `json:"fmspc_blacklist,omitempty" yaml:"fmspc_blacklist,omitempty"`

	// TDX is an optional TDX-specific policy. In case this is nil, TDX quotes are disallowed.
	TDX *TdxQuotePolicy `json:"tdx,omitempty" yaml:"tdx,omitempty"`
}

// TdxQuotePolicy is the TDX-specific quote policy.
type TdxQuotePolicy struct {
	// AllowedTdxModules are the allowed TDX modules. Empty to allow ANY Intel-signed module.
	AllowedTdxModules []TdxModulePolicy `json:"allowed_tdx_modules,omitempty" yaml:"allowed_tdx_modules,omitempty"`
}

// Verify verifies whether the TDX policy is satisfied for the given report.
func (tp *TdxQuotePolicy) Verify(report *TdReport) error {
	return tp.verifyTdxModule(report)
}

func (tp *TdxQuotePolicy) verifyTdxModule(report *TdReport) error {
	// If at least one TDX Module matches, then we are good.
	for _, allowedModule := range tp.AllowedTdxModules {
		if allowedModule.Matches(report) {
			return nil
		}
	}

	// No module matched. Iff the list of modules is empty, allow ANY Intel-signed module.
	// As per the TDX specifications, MRSIGNER is all-zero for Intel.
	if len(tp.AllowedTdxModules) == 0 && report.mrSignerSeam == TDX_MrSigner_Intel {
		return nil
	}

	return fmt.Errorf("pcs/quote: TDX module not allowed")
}

// TDX_MrSigner_Intel is the TDX module MRSIGNER for Intel (000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000).
var TDX_MrSigner_Intel [48]byte // nolint: revive

// TdxModulePolicy is the TDX module policy.
type TdxModulePolicy struct {
	// MrSeam is the optional allowed measurement of the TDX Module. In case it is nil, ANY
	// measurement is allowed and only the signer is checked.
	MrSeam *[48]byte `json:"mr_seam,omitempty" yaml:"mr_seam,omitempty"`

	// MrSignerSeam is the allowed signer of the TDX Module (zero for Intel).
	MrSignerSeam [48]byte `json:"mr_signer_seam" yaml:"mr_signer_seam"`
}

// Matches returns true iff the TDX module in the given report matches this module policy.
func (mp *TdxModulePolicy) Matches(report *TdReport) bool {
	// Check MRSEAM if set.
	if mp.MrSeam != nil {
		if *mp.MrSeam != report.mrSeam {
			return false
		}
	}

	// Check MRSIGNER.
	if mp.MrSignerSeam != report.mrSignerSeam {
		return false
	}

	return true
}
