// Package api defines the EnclaveRPC interface.
package api

// Frame is an EnclaveRPC frame.
//
// It is the Go analog of the Rust RPC frame defined in client/src/rpc/types.rs.
type Frame struct {
	Session            []byte `json:"session,omitempty"`
	UntrustedPlaintext string `json:"untrusted_plaintext,omitempty"`
	Payload            []byte `json:"payload,omitempty"`
}
