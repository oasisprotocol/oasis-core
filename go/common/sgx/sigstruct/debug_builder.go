package sigstruct

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/sgx"
)

// UnsafeDebugForEnclave returns the SIGSTRUCT corresponding to the provided
// SGX enclave binary, signed using the Fortanix Rust SDK's dummy signing key.
//
// This routine is deterministic, and MUST only ever be used for testing.
func UnsafeDebugForEnclave(sgxs []byte) ([]byte, error) {
	// Note: The key is unavailable unless DontBlameOasis is enabled.
	signingKey := sgx.UnsafeFortanixDummyKey()
	if signingKey == nil {
		return nil, fmt.Errorf("sgx/sigstruct: debug signing key unavailable")
	}

	var enclaveHash sgx.MrEnclave
	if err := enclaveHash.FromSgxsBytes(sgxs); err != nil {
		return nil, fmt.Errorf("sgx/sigstruct: failed to derive EnclaveHash: %w", err)
	}

	builder := New(
		WithAttributes(sgx.Attributes{
			Flags: sgx.AttributeDebug | sgx.AttributeMode64Bit,
			Xfrm:  3, // X87, SSE ("XFRM[1:0] must be set to 0x3")
		}),
		WithAttributesMask([2]uint64{^uint64(0), ^uint64(0)}),
		WithEnclaveHash(enclaveHash),
	)

	ret, err := builder.Sign(signingKey)
	if err != nil {
		return nil, fmt.Errorf("sgx/sigstruct: failed to sign with test key: %w", err)
	}

	return ret, nil
}
