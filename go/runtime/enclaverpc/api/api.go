// Package api defines the EnclaveRPC interface.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
)

// Transport is the EnclaveRPC transport interface.
type Transport interface {
	// CallEnclave sends the request bytes to the target enclave.
	CallEnclave(ctx context.Context, request *CallEnclaveRequest) ([]byte, error)
}

// Endpoint is an EnclaveRPC endpoint descriptor.
//
// Endpoints may be registered using the `NewEndpoint` function.
type Endpoint interface {
	// AccessControlRequired returns true if access control policy lookup is required for a specific
	// request. In case an error is returned the request is aborted.
	AccessControlRequired(ctx context.Context, request *CallEnclaveRequest) (bool, error)
}

// CallEnclaveRequest is a CallEnclave request.
type CallEnclaveRequest struct {
	RuntimeID common.Namespace `json:"runtime_id"`
	Endpoint  string           `json:"endpoint"`

	// Payload is a CBOR-serialized Frame.
	Payload []byte `json:"payload"`
}

// Frame is an EnclaveRPC frame.
//
// It is the Go analog of the Rust RPC frame defined in client/src/rpc/types.rs.
type Frame struct {
	Session            []byte `json:"session,omitempty"`
	UntrustedPlaintext string `json:"untrusted_plaintext,omitempty"`
	Payload            []byte `json:"payload,omitempty"`
}
