// Package api defines the key manager client API.
package api

import "context"

// EnclaveRPCEndpoint is the name of the key manager EnclaveRPC endpoint.
const EnclaveRPCEndpoint = "key-manager"

// Client is the key manager client interface.
type Client interface {
	// CallEnclave calls the key manager via remote EnclaveRPC.
	CallEnclave(ctx context.Context, data []byte) ([]byte, error)
}
