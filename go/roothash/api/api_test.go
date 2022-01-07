package api

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
)

func TestEvidenceHash(t *testing.T) {
	require := require.New(t)

	genesisTestHelpers.SetTestChainContext()

	// Test empty evidence.
	ev := Evidence{}
	_, err := ev.Hash()
	require.Error(err, "empty evidence hash should error")

	// Prepare valid evidence.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	sk2, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	runtimeID := common.NewTestNamespaceFromSeed([]byte("roothash/api_test/hash: runtime"), 0)
	blk := block.NewGenesisBlock(runtimeID, 0)
	signedBatch1 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        blk.Header.Round + 1,
			PreviousHash: blk.Header.EncodedHash(),
			BatchHash:    blk.Header.IORoot,
		},
	}
	err = signedBatch1.Sign(sk, runtimeID)
	require.NoError(err, "ProposalHeader.Sign")
	signed2Batch1 := signedBatch1
	signed2Batch1.NodeID = sk2.Public()
	err = signed2Batch1.Sign(sk2, runtimeID)
	require.NoError(err, "ProposalHeader.Sign")

	signedBatch2 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        blk.Header.Round + 1,
			PreviousHash: blk.Header.EncodedHash(),
			BatchHash:    hash.NewFromBytes([]byte("invalid root")),
		},
	}
	err = signedBatch2.Sign(sk, runtimeID)
	require.NoError(err, "ProposalHeader.Sign")
	signed2Batch2 := signedBatch2
	signed2Batch2.NodeID = sk2.Public()
	err = signed2Batch2.Sign(sk2, runtimeID)
	require.NoError(err, "ProposalHeader.Sign")

	// Executor commit.
	ec := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:        blk.Header.Round,
				PreviousHash: blk.Header.PreviousHash,
				IORoot:       &blk.Header.IORoot,
				StateRoot:    &blk.Header.StateRoot,
				MessagesHash: &hash.Hash{},
			},
		},
	}
	err = ec.Sign(sk, runtimeID)
	require.NoError(err, "ec.Sign")

	ev = Evidence{
		ID: runtimeID,
		EquivocationProposal: &EquivocationProposalEvidence{
			ProposalA: signedBatch1,
			ProposalB: signedBatch2,
		},
	}
	h1, err := ev.Hash()
	require.NoError(err, "Hash")

	ev = Evidence{
		ID: runtimeID,
		EquivocationExecutor: &EquivocationExecutorEvidence{
			// Same round and same signer as above evidence, hash should match.
			CommitA: ec,
			CommitB: ec,
		},
	}
	h2, err := ev.Hash()
	require.NoError(err, "Hash")
	require.EqualValues(h1, h2, "Equivocation evidence hashes for same round by same signer should match")

	ev = Evidence{
		ID: runtimeID,
		EquivocationProposal: &EquivocationProposalEvidence{
			ProposalA: signed2Batch1,
			ProposalB: signed2Batch2,
		},
	}
	h3, err := ev.Hash()
	require.NoError(err, "Hash")
	require.NotEqualValues(h1, h3, "Equivocation evidence hashes for same round by different signers shouldn't match")
}

func TestEvidenceValidateBasic(t *testing.T) {
	require := require.New(t)

	genesisTestHelpers.SetTestChainContext()

	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	rtID := common.NewTestNamespaceFromSeed([]byte("roothash/api_test: runtime1"), 0)
	rtBlk := block.NewGenesisBlock(rtID, 0)
	signedB1 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        rtBlk.Header.Round + 1,
			PreviousHash: rtBlk.Header.EncodedHash(),
			BatchHash:    rtBlk.Header.IORoot,
		},
	}
	err = signedB1.Sign(sk, rtID)
	require.NoError(err, "ProposalHeader.Sign")

	signedB2 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        rtBlk.Header.Round + 1,
			PreviousHash: rtBlk.Header.EncodedHash(),
			BatchHash:    hash.NewFromBytes([]byte("invalid root")),
		},
	}
	err = signedB2.Sign(sk, rtID)
	require.NoError(err, "ProposalHeader.Sign")

	signedCommitment1 := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          rtBlk.Header.Round + 1,
				PreviousHash:   rtBlk.Header.EncodedHash(),
				IORoot:         &rtBlk.Header.IORoot,
				StateRoot:      &rtBlk.Header.StateRoot,
				MessagesHash:   &hash.Hash{},
				InMessagesHash: &hash.Hash{},
			},
		},
	}
	err = signedCommitment1.Sign(sk, rtID)
	require.NoError(err, "signedCommitment1.Sign")

	signedCommitment2 := signedCommitment1
	signedCommitment2.Header.PreviousHash = hash.NewFromBytes([]byte("invalid hash"))
	err = signedCommitment2.Sign(sk, rtID)
	require.NoError(err, "signedCommitment2.Sign")

	for _, ev := range []struct {
		ev        Evidence
		shouldErr bool
		msg       string
	}{
		{
			Evidence{},
			true,
			"empty evidence should error",
		},
		{
			Evidence{
				ID: rtID,
				EquivocationExecutor: &EquivocationExecutorEvidence{
					CommitA: signedCommitment1,
					CommitB: signedCommitment2,
				},
				EquivocationProposal: &EquivocationProposalEvidence{
					ProposalA: signedB1,
					ProposalB: signedB2,
				},
			},
			true,
			"evidence with multiple evidence types should error",
		},
		{
			Evidence{
				ID: rtID,
				EquivocationExecutor: &EquivocationExecutorEvidence{
					CommitA: signedCommitment1,
					CommitB: signedCommitment2,
				},
			},
			false,
			"valid equivocation executor evidence",
		},
		{
			Evidence{
				ID: rtID,
				EquivocationProposal: &EquivocationProposalEvidence{
					ProposalA: signedB1,
					ProposalB: signedB2,
				},
			},
			false,
			"valid equivocation batch evidence",
		},
	} {
		err := ev.ev.ValidateBasic()
		switch ev.shouldErr {
		case true:
			require.Error(err, ev.msg)
		case false:
			require.NoError(err, ev.msg)
		}
	}
}

func TestEquivocationProposalEvidenceValidateBasic(t *testing.T) {
	require := require.New(t)

	genesisTestHelpers.SetTestChainContext()

	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	sk2, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	rt1ID := common.NewTestNamespaceFromSeed([]byte("roothash/api_test: runtime1"), 0)
	rt1Blk1 := block.NewGenesisBlock(rt1ID, 0)
	rt1Blk2 := block.NewEmptyBlock(rt1Blk1, 0, block.Normal) // Different round.
	rt1Blk3 := block.NewGenesisBlock(rt1ID, 0xDEADBEEF)      // Same round, different timestamp.

	rt2ID := common.NewTestNamespaceFromSeed([]byte("roothash/api_test: runtime2"), 0)
	rt2Blk1 := block.NewGenesisBlock(rt2ID, 0)
	rt2Blk2 := block.NewEmptyBlock(rt2Blk1, 0, block.Invalid)

	// Prepare test signed batches.
	signedR1B1 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        rt1Blk1.Header.Round + 1,
			BatchHash:    rt1Blk1.Header.IORoot,
			PreviousHash: rt1Blk1.Header.EncodedHash(),
		},
	}
	err = signedR1B1.Sign(sk, rt1ID)
	require.NoError(err, "ProposalHeader.Sign")

	signedR1B2 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        rt1Blk2.Header.Round + 1,     // Different round.
			BatchHash:    rt1Blk2.Header.IORoot,        // Different batch hash.
			PreviousHash: rt1Blk2.Header.EncodedHash(), // Different header.
		},
	}
	err = signedR1B2.Sign(sk, rt1ID)
	require.NoError(err, "ProposalHeader.Sign")

	signedR1B3 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        rt1Blk1.Header.Round + 1,                  // Same round.
			BatchHash:    hash.NewFromBytes([]byte("invalid root")), // Different batch hash.
			PreviousHash: rt1Blk1.Header.EncodedHash(),              // Same header.
		},
	}
	err = signedR1B3.Sign(sk, rt1ID)
	require.NoError(err, "ProposalHeader.Sign")

	signedR1B4 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        signedR1B1.Header.Round,        // Same round.
			BatchHash:    signedR1B1.Header.BatchHash,    // Same batch hash.
			PreviousHash: signedR1B1.Header.PreviousHash, // Same header.
		},
	}
	err = signedR1B4.Sign(sk, rt1ID)
	require.NoError(err, "ProposalHeader.Sign")

	signedR1B5 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        rt1Blk3.Header.Round + 1,     // Same round.
			BatchHash:    signedR1B1.Header.BatchHash,  // Same batch hash.
			PreviousHash: rt1Blk3.Header.EncodedHash(), // Different header for same round.
		},
	}
	err = signedR1B5.Sign(sk, rt1ID)
	require.NoError(err, "ProposalHeader.Sign")

	signed2R1B3 := signedR1B3
	signed2R1B3.NodeID = sk2.Public()
	err = signed2R1B3.Sign(sk2, rt1ID)
	require.NoError(err, "ProposalHeader.Sign")

	signedR2B1 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        rt2Blk2.Header.Round + 1,
			BatchHash:    rt2Blk2.Header.IORoot,
			PreviousHash: rt2Blk2.Header.EncodedHash(),
		},
	}
	err = signedR2B1.Sign(sk, rt2ID)
	require.NoError(err, "ProposalHeader.Sign")

	for _, ev := range []struct {
		rtID      common.Namespace
		ev        EquivocationProposalEvidence
		shouldErr bool
		msg       string
	}{
		{
			rt1ID,
			EquivocationProposalEvidence{},
			true,
			"empty evidence should error",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
			},
			true,
			"empty evidence should error",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalB: signedR1B1,
			},
			true,
			"empty evidence should error",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signedR1B1,
			},
			true,
			"same signed batch is not valid evidence",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signedR1B2,
			},
			true,
			"signed batches for different heights is not valid evidence",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signedR2B1,
			},
			true,
			"signed batches for different runtimes is not valid evidence",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signedR1B3,
			},
			false,
			"same round different IORoot is valid evidence",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signed2R1B3,
			},
			true,
			"different signer is not valid evidence",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signedR1B4,
			},
			true,
			"same round, io root and same header is not valid evidence",
		},
		{
			rt1ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signedR1B5,
			},
			false,
			"same round and io root but different header is valid evidence",
		},
		{
			rt2ID,
			EquivocationProposalEvidence{
				ProposalA: signedR1B1,
				ProposalB: signedR1B5,
			},
			true,
			"valid evidence for wrong runtime is invalid",
		},
	} {
		err := ev.ev.ValidateBasic(ev.rtID)
		switch ev.shouldErr {
		case true:
			require.Error(err, ev.msg)
		case false:
			require.NoError(err, ev.msg)
		}
	}
}

func TestEquivocationExecutorEvidenceValidateBasic(t *testing.T) {
	require := require.New(t)

	genesisTestHelpers.SetTestChainContext()

	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	sk2, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	rt1ID := common.NewTestNamespaceFromSeed([]byte("roothash/api_test: runtime1"), 0)
	rt1Blk1 := block.NewGenesisBlock(rt1ID, 0)
	rt1Blk2 := block.NewEmptyBlock(rt1Blk1, 0, block.Normal)
	rt2ID := common.NewTestNamespaceFromSeed([]byte("roothash/api_test: runtime2"), 0)

	signed1Commitment := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          rt1Blk2.Header.Round,
				PreviousHash:   rt1Blk2.Header.PreviousHash,
				IORoot:         &rt1Blk2.Header.IORoot,
				StateRoot:      &rt1Blk2.Header.StateRoot,
				MessagesHash:   &hash.Hash{},
				InMessagesHash: &hash.Hash{},
			},
		},
	}
	err = signed1Commitment.Sign(sk, rt1ID)
	require.NoError(err, "signed1Commitment.Sign")
	signed2Commitment := signed1Commitment
	signed2Commitment.NodeID = sk2.Public()
	err = signed2Commitment.Sign(sk2, rt1ID)
	require.NoError(err, "signed2Commitment.Sign")

	signed1Commitment2 := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          rt1Blk2.Header.Round,
				PreviousHash:   hash.NewFromBytes([]byte("invalid hash")),
				IORoot:         &rt1Blk2.Header.IORoot,
				StateRoot:      &rt1Blk2.Header.StateRoot,
				MessagesHash:   &hash.Hash{},
				InMessagesHash: &hash.Hash{},
			},
		},
	}
	err = signed1Commitment2.Sign(sk, rt1ID)
	require.NoError(err, "signed1Commitment2.Sign")

	// Different round.
	signed1Commitment3 := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          rt1Blk2.Header.Round + 1,
				PreviousHash:   hash.NewFromBytes([]byte("invalid hash")),
				IORoot:         &rt1Blk2.Header.IORoot,
				StateRoot:      &rt1Blk2.Header.StateRoot,
				MessagesHash:   &hash.Hash{},
				InMessagesHash: &hash.Hash{},
			},
		},
	}
	err = signed1Commitment3.Sign(sk, rt1ID)
	require.NoError(err, "signed1Commitment3.Sign")

	// Invalid.
	signed1Invalid := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          rt1Blk2.Header.Round,
				PreviousHash:   hash.NewFromBytes([]byte("invalid hash")),
				IORoot:         nil,
				StateRoot:      &rt1Blk2.Header.StateRoot,
				MessagesHash:   nil,
				InMessagesHash: nil,
			},
		},
	}
	err = signed1Invalid.Sign(sk, rt1ID)
	require.NoError(err, "signed1Invalid.Sign")

	// Failure indicating.
	signedFailure1 := signed1Commitment
	signedFailure1.Header.SetFailure(commitment.FailureStateUnavailable)
	err = signedFailure1.Sign(sk, rt1ID)
	require.NoError(err, "signedFailure1.Sign")

	signedFailure2 := signed1Commitment
	signedFailure2.Header.SetFailure(commitment.FailureUnknown)
	err = signedFailure2.Sign(sk, rt1ID)
	require.NoError(err, "signedFailure2.Sign")

	for _, ev := range []struct {
		rtID      common.Namespace
		ev        EquivocationExecutorEvidence
		shouldErr bool
		msg       string
	}{
		{
			rt1ID,
			EquivocationExecutorEvidence{},
			true,
			"empty evidence should error",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
			},
			true,
			"empty evidence should error",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitB: signed1Commitment,
			},
			true,
			"empty evidence should error",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
				CommitB: signed1Commitment,
			},
			true,
			"same signed commitment is not valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
				CommitB: signed1Commitment3,
			},
			true,
			"signed commitments for different rounds is not valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
				CommitB: signed1Invalid,
			},
			true,
			"non valid commitment is not valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Invalid,
				CommitB: signed1Commitment,
			},
			true,
			"non valid commitment not valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signedFailure1,
				CommitB: signedFailure1,
			},
			true,
			"same failure indicating is not valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signedFailure1,
				CommitB: signedFailure2,
			},
			false,
			"different failure indicating reason is valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
				CommitB: signed2Commitment,
			},
			true,
			"different signer is not valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
				CommitB: signed1Commitment2,
			},
			false,
			"valid evidence",
		},
		{
			rt1ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
				CommitB: signedFailure1,
			},
			false,
			"valid evidence",
		},
		{
			rt2ID,
			EquivocationExecutorEvidence{
				CommitA: signed1Commitment,
				CommitB: signedFailure1,
			},
			true,
			"valid evidence for wrong runtime is invalid",
		},
	} {
		err := ev.ev.ValidateBasic(ev.rtID)
		switch ev.shouldErr {
		case true:
			require.Error(err, ev.msg)
		case false:
			require.NoError(err, ev.msg)
		}
	}
}
