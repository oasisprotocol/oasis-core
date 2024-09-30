// Package api defines the key manager client API.
package api

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
)

// EnclaveRPCEndpoint is the name of the key manager EnclaveRPC endpoint.
const EnclaveRPCEndpoint = "key-manager"

// Client is the key manager client interface.
type Client interface {
	// CallEnclaveDeprecated calls the key manager via remote EnclaveRPC.
	//
	// The node to which the call will be routed is chosen at random from the key manager committee
	// members. The latter can be restricted by specifying a non-empty list of allowed nodes.
	//
	// The provided peer feedback is optional feedback on the peer that handled the last EnclaveRPC
	// request (if any) which may be used to inform the routing decision.
	//
	// Deprecated: This method is deprecated and will be removed in future versions.
	CallEnclaveDeprecated(ctx context.Context, data []byte, nodes []signature.PublicKey, kind enclaverpc.Kind, pf *enclaverpc.PeerFeedback) ([]byte, signature.PublicKey, error)

	// CallEnclave calls the key manager via remote enclave RPC.
	//
	// The node to which the call will be routed is chosen at random from the key manager committee
	// members. The latter can be restricted by specifying a non-empty list of allowed nodes.
	CallEnclave(ctx context.Context, requestID uint64, data []byte, nodes []signature.PublicKey, kind enclaverpc.Kind) (*EnclaveResponse, error)

	// SubmitPeerFeedback submits peer feedback for the given request.
	SubmitPeerFeedback(requestID uint64, feedback enclaverpc.PeerFeedback)
}

// EnclaveResponse is the enclave response.
type EnclaveResponse struct {
	// Data contains the actual response data.
	Data []byte

	// Node is the public key of the node that generated the response.
	Node signature.PublicKey
}
