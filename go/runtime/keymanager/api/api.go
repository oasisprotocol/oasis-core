// Package api defines the key manager client API.
package api

import (
	"context"

	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
)

// EnclaveRPCEndpoint is the name of the key manager EnclaveRPC endpoint.
const EnclaveRPCEndpoint = "key-manager"

// Client is the key manager client interface.
type Client interface {
	// CallEnclave calls the key manager via remote EnclaveRPC.
	//
	// The provided peer feedback is optional feedback on the peer that handled the last EnclaveRPC
	// request (if any) which may be used to inform the routing decision.
	CallEnclave(ctx context.Context, data []byte, pf *enclaverpc.PeerFeedback) ([]byte, error)
}
