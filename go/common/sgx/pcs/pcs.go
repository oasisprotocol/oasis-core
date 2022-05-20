package pcs

import (
	"context"
	"time"
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
// In case of successful verification it returns the TCB level.
func (bnd *QuoteBundle) Verify(ts time.Time) (*TCBLevel, error) {
	var quote Quote
	if err := quote.UnmarshalBinary(bnd.Quote); err != nil {
		return nil, err
	}
	return quote.Verify(ts, &bnd.TCB)
}
