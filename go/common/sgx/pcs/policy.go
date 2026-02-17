package pcs

import (
	"fmt"
	"maps"
	"slices"
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

// Merge merges two QuotePolicies into one, taking more restrictive configuration into account.
//
// TODO:
//   - What if FMSCPWhitelist has no intersection (same applies for TDXQuotePolicy)?
//   - Should we even allow registration of such runtime descriptor?
//   - Finish TDX quote policy merge (ugly).
//   - Unit tests.
//   - Merge should produce independent copies to not accidentally mutate stuff.
func (p *QuotePolicy) Merge(o *QuotePolicy) *QuotePolicy {
	if p == nil {
		return o
	}

	if o == nil {
		return p
	}

	merged := &QuotePolicy{
		Disabled:                   p.Disabled || o.Disabled,
		TCBValidityPeriod:          min(p.TCBValidityPeriod, o.TCBValidityPeriod),
		MinTCBEvaluationDataNumber: max(p.MinTCBEvaluationDataNumber, o.MinTCBEvaluationDataNumber),
	}

	func() {
		if len(p.FMSPCWhitelist) == 0 {
			merged.FMSPCWhitelist = o.FMSPCWhitelist
			return
		}

		if len(o.FMSPCWhitelist) == 0 {
			merged.FMSPCWhitelist = p.FMSPCWhitelist
			return
		}

		intersect := make(map[string]struct{}, len(p.FMSPCWhitelist))
		for _, fmspc := range p.FMSPCWhitelist {
			intersect[fmspc] = struct{}{}
		}
		for _, fmspc := range o.FMSPCWhitelist {
			if _, ok := intersect[fmspc]; ok {
				merged.FMSPCWhitelist = append(merged.FMSPCWhitelist, fmspc)
			}
		}

		// Preventing no intersection meaning allow any.
		if len(merged.FMSPCWhitelist) == 0 {
			merged.Disabled = true
		}

	}()

	union := make(map[string]struct{}, len(p.FMSPCBlacklist)+len(o.FMSPCBlacklist))
	for _, fmspc := range append(p.FMSPCBlacklist, o.FMSPCBlacklist...) {
		union[fmspc] = struct{}{}
	}
	merged.FMSPCBlacklist = slices.Collect(maps.Keys(union))
	slices.Sort(merged.FMSPCBlacklist)

	merged.TDX = p.TDX.Merge(o.TDX)
	return merged
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

func (tp *TdxQuotePolicy) Merge(o *TdxQuotePolicy) *TdxQuotePolicy {
	if tp == nil || o == nil {
		return nil
	}

	if len(tp.AllowedTdxModules) == 0 {
		return o
	}

	if len(o.AllowedTdxModules) == 0 {
		return tp
	}

	// TODO
	// Merge the TDXQuotePolicy.

	return o
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
