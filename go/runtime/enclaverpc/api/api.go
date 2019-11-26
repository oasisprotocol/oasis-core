// Package api defines the EnclaveRPC interface.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

// Transport is the EnclaveRPC transport interface.
type Transport interface {
	// CallEnclave sends the request bytes to the target enclave.
	CallEnclave(ctx context.Context, request *CallEnclaveRequest) ([]byte, error)
}

// CallEnclaveRequest is a CallEnclave request.
type CallEnclaveRequest struct {
	RuntimeID signature.PublicKey `json:"runtime_id"`
	Endpoint  string              `json:"endpoint"`

	Payload []byte `json:"payload"`
}
