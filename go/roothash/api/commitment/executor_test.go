package commitment

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

func TestConsistentHash(t *testing.T) {
	// NOTE: These hashes MUST be synced with runtime/src/common/roothash.rs.
	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")

	var empty ComputeResultsHeader
	require.EqualValues(t, emptyHeaderHash.String(), empty.EncodedHash().String())

	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var populatedHeaderHash hash.Hash
	_ = populatedHeaderHash.UnmarshalHex("8459a9e6e3341cd2df5ada5737469a505baf92397aaa88b7100915324506d843")

	populated := ComputeResultsHeader{
		Round:          42,
		PreviousHash:   emptyHeaderHash,
		IORoot:         &emptyRoot,
		StateRoot:      &emptyRoot,
		MessagesHash:   &emptyRoot,
		InMessagesHash: &emptyRoot,
	}
	require.EqualValues(t, populatedHeaderHash.String(), populated.EncodedHash().String())
}

func TestValidateBasic(t *testing.T) {
	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")

	body := ExecutorCommitment{
		Header: ExecutorCommitmentHeader{
			ComputeResultsHeader: ComputeResultsHeader{
				Round:          42,
				PreviousHash:   emptyHeaderHash,
				IORoot:         &emptyRoot,
				StateRoot:      &emptyRoot,
				MessagesHash:   &emptyRoot,
				InMessagesHash: &emptyRoot,
			},
			RAKSignature: &signature.RawSignature{},
		},
		Messages: nil,
	}

	for _, tc := range []struct {
		name      string
		fn        func(ExecutorCommitment) ExecutorCommitment
		shouldErr bool
	}{
		{
			"Ok",
			func(ec ExecutorCommitment) ExecutorCommitment { return ec },
			false,
		},
		{
			"Bad IORoot",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.IORoot = nil
				return ec
			},
			true,
		},
		{
			"Bad StateRoot",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.StateRoot = nil
				return ec
			},
			true,
		},
		{
			"Bad MessagesHash",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.MessagesHash = nil
				return ec
			},
			true,
		},
		{
			"Bad runtime messages",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Messages = []message.Message{
					{}, // A message without any variant is invalid.
				}
				return ec
			},
			true,
		},
		{
			"Bad Failure",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.SetFailure(10)
				return ec
			},
			true,
		},
		{
			"Bad Failure (existing IORoot)",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.Failure = FailureUnknown
				// ec.Header.IORoot is set.
				ec.Header.StateRoot = nil
				ec.Header.MessagesHash = nil
				ec.Header.InMessagesHash = nil
				return ec
			},
			true,
		},
		{
			"Bad Failure (existing StateRoot)",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.Failure = FailureUnknown
				ec.Header.IORoot = nil
				// ec.Header.StateRoot is set.
				ec.Header.MessagesHash = nil
				ec.Header.InMessagesHash = nil
				return ec
			},
			true,
		},
		{
			"Bad Failure (existing MessagesHash)",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.Failure = FailureUnknown
				ec.Header.IORoot = nil
				ec.Header.StateRoot = nil
				// ec.Header.MessagesHash is set.
				ec.Header.InMessagesHash = nil
				return ec
			},
			true,
		},
		{
			"Bad Failure (existing InMessagesHash)",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.Failure = FailureUnknown
				ec.Header.IORoot = nil
				ec.Header.StateRoot = nil
				ec.Header.MessagesHash = nil
				// ec.Header.InMessagesHash is set.
				return ec
			},
			true,
		},
		{
			"Ok Failure",
			func(ec ExecutorCommitment) ExecutorCommitment {
				ec.Header.SetFailure(FailureUnknown)
				return ec
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
