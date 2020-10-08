package commitment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestValidateBasic(t *testing.T) {
	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")

	body := ComputeBody{
		Header: ComputeResultsHeader{
			Round:        42,
			PreviousHash: emptyHeaderHash,
			IORoot:       &emptyRoot,
			StateRoot:    &emptyRoot,
			Messages:     nil,
		},
		TxnSchedSig:       signature.Signature{},
		InputRoot:         emptyRoot,
		StorageSignatures: []signature.Signature{{}},
		RakSig:            &signature.RawSignature{},
	}

	for _, tc := range []struct {
		name      string
		fn        func(ComputeBody) ComputeBody
		shouldErr bool
	}{
		{
			"Ok",
			func(b ComputeBody) ComputeBody { return b },
			false,
		},
		{
			"Bad IORoot",
			func(b ComputeBody) ComputeBody {
				b.Header.IORoot = nil
				return b
			},
			true,
		},
		{
			"Bad StateRoot",
			func(b ComputeBody) ComputeBody {
				b.Header.StateRoot = nil
				return b
			},
			true,
		},
		{
			"Bad Failure",
			func(b ComputeBody) ComputeBody {
				b.SetFailure(10)
				return b
			},
			true,
		},
		{
			"Bad Failure",
			func(b ComputeBody) ComputeBody {
				b.Failure = FailureStorageUnavailable
				return b
			},
			true,
		},
		{
			"Ok Failure",
			func(b ComputeBody) ComputeBody {
				b.SetFailure(FailureStorageUnavailable)
				return b
			},
			false,
		},
	} {
		b := tc.fn(body)
		err := b.ValidateBasic()
		switch tc.shouldErr {
		case true:
			require.Error(t, err, "ValidateBasic(%s)", tc.name)
		case false:
			require.NoError(t, err, "ValidateBasic(%s)", tc.name)
		}
	}
}
