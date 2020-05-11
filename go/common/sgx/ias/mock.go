package ias

import (
	"encoding/json"
	"time"
)

type mockAVR struct {
	Version               int    `json:"version"`
	Timestamp             string `json:"timestamp"`
	ISVEnclaveQuoteStatus string `json:"isvEnclaveQuoteStatus"`
	ISVEnclaveQuoteBody   []byte `json:"isvEnclaveQuoteBody"`
	Nonce                 string `json:"nonce,omitempty"`
}

// NewMockAVR returns a mock AVR for the given quote and nonce, after doing
// some light sanity checking on the quote.
//
// This is only useful for runtimes with with AVR verification disabled at
// compile time (ie: built with `OASIS_UNSAFE_SKIP_AVR_VERIFY=1`).
func NewMockAVR(quote []byte, nonce string) ([]byte, error) {
	mockAVR := &mockAVR{
		Version:               4,
		Timestamp:             time.Now().UTC().Format(TimestampFormat),
		ISVEnclaveQuoteStatus: "OK",
		ISVEnclaveQuoteBody:   quote[:quoteLen],
		Nonce:                 nonce,
	}

	var q Quote
	err := q.UnmarshalBinary(mockAVR.ISVEnclaveQuoteBody)
	if err != nil {
		return nil, err
	}
	if err = q.Verify(); err != nil {
		return nil, err
	}

	return json.Marshal(mockAVR)
}
