package pcs

import (
	"context"
	"time"
)

// Client is an Intel SGX PCS client interface.
type Client interface {
	// GetTCBInfo retrieves the signed TCB info for the given platform.
	GetTCBInfo(ctx context.Context, fmspc []byte) (*SignedTCBInfo, error)

	// GetQEIdentity retrieves the signed Intel QE identity.
	GetQEIdentity(ctx context.Context) (*SignedQEIdentity, error)
}

// Config is the Intel SGX PCS client configuration.
type Config struct {
	// SubscriptionKey is the Intel PCS API key used for client authentication (needed for PCK
	// certificate retrieval).
	SubscriptionKey string
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
