package ias

import (
	"time"

	"github.com/oasislabs/ekiden/go/common/json"
)

type mockAVR struct {
	Timestamp             string `codec:"timestamp"`
	ISVEnclaveQuoteStatus string `codec:"isvEnclaveQuoteStatus"`
	ISVEnclaveQuoteBody   []byte `codec:"isvEnclaveQuoteBody"`
	Nonce                 string `codec:"nonce,omitempty"`
}

// NewMockAVR returns a mock AVR for the given quote and nonce, after doing
// some light sanity checking on the quote.
//
// This is only useful for runtimes with with AVR verification disabled at
// compile time (ie: built with `EKIDEN_UNSAFE_SKIP_AVR_VERIFY=1`).
func NewMockAVR(quote []byte, nonce string) ([]byte, error) {
	mockAVR := &mockAVR{
		Timestamp:             time.Now().UTC().Format(TimestampFormat),
		ISVEnclaveQuoteStatus: "OK",
		ISVEnclaveQuoteBody:   quote[:QuoteLen],
		Nonce:                 nonce,
	}

	q, err := DecodeQuote(mockAVR.ISVEnclaveQuoteBody)
	if err != nil {
		return nil, err
	}
	if err = q.Verify(); err != nil {
		return nil, err
	}

	return json.Marshal(mockAVR), nil
}
