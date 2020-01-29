package api

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	enclaverpc "github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
)

var (
	// Make sure this always matches the appropriate method in
	// `keymanager-runtime/src/methods.rs`.
	getPublicKeyRequestMethod = "get_public_key"

	// requestSkipPolicyCheck defines if policy check is needed for the request.
	requestSkipPolicyCheck = func(req interface{}) bool {
		r, ok := req.(*enclaverpc.CallEnclaveRequest)
		if !ok {
			return false
		}

		// Check if policy access is needed.
		skipPolicyCheck, err := payloadSkipPolicyCheck(r.Payload)
		if err != nil {
			return false
		}

		return skipPolicyCheck
	}

	// Service is the Keymanager enclave gRPC service.
	Service = enclaverpc.NewService(ModuleName, requestSkipPolicyCheck)
)

func payloadSkipPolicyCheck(data cbor.RawMessage) (bool, error) {
	// Unpack the payload, get method from Frame.
	var f enclaverpc.Frame
	if err := cbor.Unmarshal(data, &f); err != nil {
		return false, fmt.Errorf("unable to unpack Frame: %w", err)
	}

	if f.UntrustedPlaintext == "" {
		// Anyone can connect.
		return true, nil
	}

	if f.UntrustedPlaintext == getPublicKeyRequestMethod {
		// Anyone can get public keys.
		// Note that this is also checked in the enclave, so if the node lied
		// about what method it's using, we will know.
		return true, nil
	}

	// Defer to access control to check the policy.
	return false, nil
}
