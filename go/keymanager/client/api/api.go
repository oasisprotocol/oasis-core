// Package api defines the key manager client API.
package api

import "context"

// Client is the key manager client interface.
type Client interface {
	// CallRemote calls the key manager via remote EnclaveRPC.
	CallRemote(ctx context.Context, data []byte) ([]byte, error)

	// Initialized returns a channel which is closed when the key manager client initialization has
	// completed and the client is ready to service requests.
	Initialized() <-chan struct{}
}
