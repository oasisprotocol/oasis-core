package pcs

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

var (
	unsafeSkipVerify         bool
	unsafeAllowDebugEnclaves bool

	mrSignerBlacklist = make(map[sgx.MrSigner]bool)
)

// Client is an Intel SGX PCS client interface.
type Client interface {
	// GetTCBBundle retrieves the signed TCB artifacts needed to verify a quote.
	GetTCBBundle(ctx context.Context, teeType TeeType, fmspc []byte, tcbEvaluationDataNumber uint32) (*TCBBundle, error)

	// GetTCBEvaluationDataNumbers retrieves the list of TCB evaluation data numbers.
	GetTCBEvaluationDataNumbers(ctx context.Context, teeType TeeType) ([]uint32, error)

	// GetPCKCertificateChain retrieves the PCK certificate chain for the given platform data or PPID.
	//
	// If platform data is provided, it is used instead of the encrypted PPID for certificate retrieval.
	GetPCKCertificateChain(ctx context.Context, platformData []byte, encPpid [384]byte, cpusvn [16]byte, pcesvn uint16, pceid uint16) ([]*x509.Certificate, error)
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

// SetSkipVerify will disable quote signature verification for the remainder of the process'
// lifetime.
func SetSkipVerify() {
	unsafeSkipVerify = true
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
