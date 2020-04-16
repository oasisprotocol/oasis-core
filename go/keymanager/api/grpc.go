package api

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	enclaverpc "github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
)

var (
	// Make sure this always matches the appropriate method in
	// `keymanager-runtime/src/methods.rs`.
	getPublicKeyRequestMethod = "get_public_key"
)

type enclaveRPCEndpoint struct {
}

// Implements enclaverpc.Endpoint.
func (e *enclaveRPCEndpoint) AccessControlRequired(ctx context.Context, request *enclaverpc.CallEnclaveRequest) (bool, error) {
	// Unpack the payload, get method from Frame.
	var f enclaverpc.Frame
	if err := cbor.Unmarshal(request.Payload, &f); err != nil {
		return false, fmt.Errorf("keymanager: unable to unpack EnclaveRPC frame: %w", err)
	}

	switch f.UntrustedPlaintext {
	case "":
		// Anyone can connect.
		return false, nil
	case getPublicKeyRequestMethod:
		// Anyone can get public keys.
		//
		// Note that this is also checked in the enclave, so if the node lied
		// about what method it's using, we will know.
		return false, nil
	default:
		// Defer to access control to check the policy.
		return true, nil
	}
}

func init() {
	enclaverpc.NewEndpoint(EnclaveRPCEndpoint, &enclaveRPCEndpoint{})
}
