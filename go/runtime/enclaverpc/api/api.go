// Package api defines the EnclaveRPC interface.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
)

// Transport is the EnclaveRPC transport interface.
type Transport interface {
	// CallEnclave sends the request bytes to the target enclave.
	CallEnclave(ctx context.Context, request *CallEnclaveRequest) ([]byte, error)
}

// CallEnclaveRequest is a CallEnclave request.
type CallEnclaveRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Endpoint  string           `json:"endpoint"`

	// Payload is a CBOR-serialized Frame.
	Payload cbor.RawMessage `json:"payload"`
}

// Frame is an EnclaveRPC frame.
//
// It is the Go analog of the Rust RPC frame defined in client/src/rpc/client.rs.
type Frame struct {
	Session            []byte `json:"session,omitempty"`
	UntrustedPlaintext string `json:"untrusted_plaintext,omitempty"`
	Payload            []byte `json:"payload,omitempty"`
}
