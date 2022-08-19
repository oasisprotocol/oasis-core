package pcs

import (
	"context"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

var (
	unsafeAllowDebugEnclaves bool

	mrSignerBlacklist = make(map[sgx.MrSigner]bool)
)

// Client is an Intel SGX PCS client interface.
type Client interface {
	// GetTCBBundle retrieves the signed TCB artifacts needed to verify a quote.
	GetTCBBundle(ctx context.Context, fmspc []byte) (*TCBBundle, error)
}

// QuoteBundle is an attestation quote together with the TCB bundle required for its verification.
type QuoteBundle struct {
	// Quote is the raw attestation quote.
	Quote []byte `json:"quote"`

	// TCB is the TCB bundle required to verify an attestation quote.
	TCB TCBBundle `json:"tcb"`
}

// Verify verifies the quote bundle.
//
// In case of successful verification it returns the verified quote.
func (bnd *QuoteBundle) Verify(policy *QuotePolicy, ts time.Time) (*sgx.VerifiedQuote, error) {
	var quote Quote
	if err := quote.UnmarshalBinary(bnd.Quote); err != nil {
		return nil, err
	}
	return quote.Verify(policy, ts, &bnd.TCB)
}

// SetAllowDebugEnclaves will enable running and communicating with enclaves with debug flag enabled
// in report body for the remainder of the process' lifetime.
func SetAllowDebugEnclaves() {
	unsafeAllowDebugEnclaves = true
}

// UnsetAllowDebugEnclaves will disable running and communicating with enclaves with debug flag
// enabled in report body for the remainder of the process' lifetime.
func UnsetAllowDebugEnclaves() {
	unsafeAllowDebugEnclaves = false
}

// BuildMrSignerBlacklist builds the MRSIGNER blacklist.
func BuildMrSignerBlacklist(allowTestKeys bool) {
	if !allowTestKeys {
		for _, v := range []string{
			sgx.FortanixDummyMrSigner.String(),
		} {
			var signer sgx.MrSigner
			if err := signer.UnmarshalHex(v); err != nil {
				panic("pcs: failed to decode MRSIGNER: " + v)
			}
			mrSignerBlacklist[signer] = true
		}
	}
}
