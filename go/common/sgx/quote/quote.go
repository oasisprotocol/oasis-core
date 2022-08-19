package quote

import (
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/ias"
	"github.com/oasisprotocol/oasis-core/go/common/sgx/pcs"
)

// Quote is an unverified SGX remote attestation quote, depending on the attestation scheme.
type Quote struct {
	IAS *ias.AVRBundle   `json:"ias,omitempty"`
	PCS *pcs.QuoteBundle `json:"pcs,omitempty"`
}

// Verify verifies the SGX remote attestation quote.
func (q *Quote) Verify(policy *Policy, ts time.Time) (*sgx.VerifiedQuote, error) {
	// Make sure exactly one quote kind is set.
	if !common.ExactlyOneTrue(
		q.IAS != nil,
		q.PCS != nil,
	) {
		return nil, fmt.Errorf("exactly one quote kind must be set")
	}

	if policy == nil {
		policy = &Policy{}
	}

	switch {
	case q.IAS != nil:
		// IAS.
		avr, err := q.IAS.Open(policy.IAS, ias.IntelTrustRoots, ts)
		if err != nil {
			return nil, err
		}

		// Extract the original ISV quote.
		isvQuote, err := avr.Quote()
		if err != nil {
			return nil, err
		}

		return &sgx.VerifiedQuote{
			ReportData: isvQuote.Report.ReportData[:],
			Identity: sgx.EnclaveIdentity{
				MrEnclave: isvQuote.Report.MRENCLAVE,
				MrSigner:  isvQuote.Report.MRSIGNER,
			},
		}, nil
	case q.PCS != nil:
		// PCS.
		return q.PCS.Verify(policy.PCS, ts)
	default:
		return nil, fmt.Errorf("exactly one quote kind must be set")
	}
}

// Policy is the quote validity policy.
type Policy struct {
	IAS *ias.QuotePolicy `json:"ias,omitempty"`
	PCS *pcs.QuotePolicy `json:"pcs,omitempty"`
}
