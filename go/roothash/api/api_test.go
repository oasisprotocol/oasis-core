package api

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
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
	batch1 := &commitment.ProposedBatch{
		IORoot:            blk.Header.IORoot,
		StorageSignatures: []signature.Signature{},
		Header:            blk.Header,
	}
	signedBatch1, err := commitment.SignProposedBatch(sk, batch1)
	require.NoError(err, "SignProposedBatch")
	signed2Batch1, err := commitment.SignProposedBatch(sk2, batch1)
	require.NoError(err, "SignedProposedBatch")

	batch2 := &commitment.ProposedBatch{
		IORoot:            hash.NewFromBytes([]byte("invalid root")),
		StorageSignatures: []signature.Signature{},
		Header:            blk.Header,
	}
	signedBatch2, err := commitment.SignProposedBatch(sk, batch2)
	require.NoError(err, "SignProposedBatch")
	signed2Batch2, err := commitment.SignProposedBatch(sk2, batch2)
	require.NoError(err, "SignedProposedBatch")

	// Executor commit.
	body := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        blk.Header.Round,
			PreviousHash: blk.Header.PreviousHash,
			IORoot:       &blk.Header.IORoot,
			StateRoot:    &blk.Header.StateRoot,
			MessagesHash: &hash.Hash{},
		},
	}
	signedCommitment1, err := commitment.SignExecutorCommitment(sk, &body)
	require.NoError(err, "SignExecutorCommitment")

	ev = Evidence{
		ID: runtimeID,
		EquivocationBatch: &EquivocationBatchEvidence{
			BatchA: *signedBatch1,
			BatchB: *signedBatch2,
		},
	}
	h1, err := ev.Hash()
	require.NoError(err, "Hash")

	ev = Evidence{
		ID: runtimeID,
		EquivocationExecutor: &EquivocationExecutorEvidence{
			// Same round and same signer as above evidence, hash should match.
			CommitA: *signedCommitment1,
			CommitB: *signedCommitment1,
		},
	}
	h2, err := ev.Hash()
	require.NoError(err, "Hash")
	require.EqualValues(h1, h2, "Equivocation evidence hashes for same round by same signer should match")

	ev = Evidence{
		ID: runtimeID,
		EquivocationBatch: &EquivocationBatchEvidence{
			BatchA: *signed2Batch1,
			BatchB: *signed2Batch2,
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
	rtBatch1 := &commitment.ProposedBatch{
		IORoot:            rtBlk.Header.IORoot,
		StorageSignatures: []signature.Signature{},
		Header:            rtBlk.Header,
	}
	signedB1, err := commitment.SignProposedBatch(sk, rtBatch1)
	require.NoError(err, "SignProposedBatch")

	rtBatch2 := &commitment.ProposedBatch{
		IORoot:            hash.NewFromBytes([]byte("invalid root")),
		StorageSignatures: []signature.Signature{},
		Header:            rtBlk.Header,
	}
	signedB2, err := commitment.SignProposedBatch(sk, rtBatch2)
	require.NoError(err, "SignProposedBatch")

	body := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        rtBlk.Header.Round,
			PreviousHash: rtBlk.Header.PreviousHash,
			IORoot:       &rtBlk.Header.IORoot,
			StateRoot:    &rtBlk.Header.StateRoot,
			MessagesHash: &hash.Hash{},
		},
	}
	signedCommitment1, err := commitment.SignExecutorCommitment(sk, &body)
	require.NoError(err, "SignExecutorCommitment")

	body.Header.PreviousHash = hash.NewFromBytes([]byte("invalid hash"))
	signedCommitment2, err := commitment.SignExecutorCommitment(sk, &body)
	require.NoError(err, "SignExecutorCommitment")

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
					CommitA: *signedCommitment1,
					CommitB: *signedCommitment2,
				},
				EquivocationBatch: &EquivocationBatchEvidence{
					BatchA: *signedB1,
					BatchB: *signedB2,
				},
			},
			true,
			"evidence with multiple evidence types should error",
		},
		{
			Evidence{
				ID: rtID,
				EquivocationExecutor: &EquivocationExecutorEvidence{
					CommitA: *signedCommitment1,
					CommitB: *signedCommitment2,
				},
			},
			false,
			"valid equivocation executor evidence",
		},
		{
			Evidence{
				ID: rtID,
				EquivocationBatch: &EquivocationBatchEvidence{
					BatchA: *signedB1,
					BatchB: *signedB2,
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

func TestEquivocationBatchEvidenceValidateBasic(t *testing.T) {
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
	rt2Blk1 := block.NewGenesisBlock(rt2ID, 0)
	rt2Blk2 := block.NewEmptyBlock(rt2Blk1, 0, block.Invalid)

	// Prepare test signed batches.
	rt1Batch1 := &commitment.ProposedBatch{
		IORoot:            rt1Blk1.Header.IORoot,
		StorageSignatures: []signature.Signature{},
		Header:            rt1Blk1.Header,
	}
	signedR1B1, err := commitment.SignProposedBatch(sk, rt1Batch1)
	require.NoError(err, "SignProposedBatch")

	rt1Batch2 := &commitment.ProposedBatch{
		IORoot:            rt1Blk2.Header.IORoot,
		StorageSignatures: []signature.Signature{},
		Header:            rt1Blk2.Header,
	}
	signedR1B2, err := commitment.SignProposedBatch(sk, rt1Batch2)
	require.NoError(err, "SignProposedBatch")

	rt1Batch3 := &commitment.ProposedBatch{
		IORoot:            hash.NewFromBytes([]byte("invalid root")),
		StorageSignatures: []signature.Signature{},
		Header:            rt1Blk1.Header,
	}
	signedR1B3, err := commitment.SignProposedBatch(sk, rt1Batch3)
	require.NoError(err, "SignProposedBatch")

	signed2R1B3, err := commitment.SignProposedBatch(sk2, rt1Batch3)
	require.NoError(err, "SignProposedBatch")

	rt2Batch1 := &commitment.ProposedBatch{
		IORoot:            rt2Blk2.Header.IORoot,
		StorageSignatures: []signature.Signature{},
		Header:            rt2Blk2.Header,
	}
	signedR2B1, err := commitment.SignProposedBatch(sk, rt2Batch1)
	require.NoError(err, "SignProposedBatch")

	for _, ev := range []struct {
		ev        EquivocationBatchEvidence
		shouldErr bool
		msg       string
	}{
		{
			EquivocationBatchEvidence{},
			true,
			"empty evidence should error",
		},
		{
			EquivocationBatchEvidence{
				BatchA: *signedR1B1,
			},
			true,
			"empty evidence should error",
		},
		{
			EquivocationBatchEvidence{
				BatchB: *signedR1B1,
			},
			true,
			"empty evidence should error",
		},
		{
			EquivocationBatchEvidence{
				BatchA: *signedR1B1,
				BatchB: *signedR1B1,
			},
			true,
			"same signed batch is not valid evidence",
		},
		{
			EquivocationBatchEvidence{
				BatchA: *signedR1B1,
				BatchB: *signedR1B2,
			},
			true,
			"signed batches for different heights is not valid evidence",
		},
		{
			EquivocationBatchEvidence{
				BatchA: *signedR1B1,
				BatchB: *signedR2B1,
			},
			true,
			"signed batches for different runtimes is not valid evidence",
		},
		{
			EquivocationBatchEvidence{
				BatchA: *signedR1B1,
				BatchB: *signedR1B3,
			},
			false,
			"same height different IORoot is valid evidence",
		},
		{
			EquivocationBatchEvidence{
				BatchA: *signedR1B1,
				BatchB: *signed2R1B3,
			},
			true,
			"different signer is not valid evidence",
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

	body := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        rt1Blk2.Header.Round,
			PreviousHash: rt1Blk2.Header.PreviousHash,
			IORoot:       &rt1Blk2.Header.IORoot,
			StateRoot:    &rt1Blk2.Header.StateRoot,
			MessagesHash: &hash.Hash{},
		},
	}
	signed1Commitment, err := commitment.SignExecutorCommitment(sk, &body)
	require.NoError(err, "SignExecutorCommitment")
	signed2Commitment, err := commitment.SignExecutorCommitment(sk2, &body)
	require.NoError(err, "SignExecutorCommitment")

	body2 := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        rt1Blk2.Header.Round,
			PreviousHash: hash.NewFromBytes([]byte("invalid hash")),
			IORoot:       &rt1Blk2.Header.IORoot,
			StateRoot:    &rt1Blk2.Header.StateRoot,
			MessagesHash: &hash.Hash{},
		},
	}
	signed1Commitment2, err := commitment.SignExecutorCommitment(sk, &body2)
	require.NoError(err, "SignExecutorCommitment")

	// Different round.
	body3 := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        rt1Blk2.Header.Round + 1,
			PreviousHash: hash.NewFromBytes([]byte("invalid hash")),
			IORoot:       &rt1Blk2.Header.IORoot,
			StateRoot:    &rt1Blk2.Header.StateRoot,
			MessagesHash: &hash.Hash{},
		},
	}
	signed1Commitment3, err := commitment.SignExecutorCommitment(sk, &body3)
	require.NoError(err, "SignExecutorCommitment")

	// Invalid.
	invalidBody := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        rt1Blk2.Header.Round,
			PreviousHash: hash.NewFromBytes([]byte("invalid hash")),
			IORoot:       nil,
			StateRoot:    &rt1Blk2.Header.StateRoot,
			MessagesHash: nil,
		},
	}
	signed1Invalid, err := commitment.SignExecutorCommitment(sk, &invalidBody)
	require.NoError(err, "SignExecutorCommitment")

	// Failure indicating.
	failureBody1 := body
	failureBody1.SetFailure(commitment.FailureStorageUnavailable)
	signedFailure1, err := commitment.SignExecutorCommitment(sk, &failureBody1)
	require.NoError(err, "SignExecutorCommitment")

	failureBody2 := body
	failureBody2.SetFailure(commitment.FailureUnknown)
	signedFailure2, err := commitment.SignExecutorCommitment(sk, &failureBody2)
	require.NoError(err, "SignExecutorCommitment")

	for _, ev := range []struct {
		ev        EquivocationExecutorEvidence
		shouldErr bool
		msg       string
	}{
		{
			EquivocationExecutorEvidence{},
			true,
			"empty evidence should error",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Commitment,
			},
			true,
			"empty evidence should error",
		},
		{
			EquivocationExecutorEvidence{
				CommitB: *signed1Commitment,
			},
			true,
			"empty evidence should error",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Commitment,
				CommitB: *signed1Commitment,
			},
			true,
			"same signed commitment is not valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Commitment,
				CommitB: *signed1Commitment3,
			},
			true,
			"signed commitments for different rounds is not valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Commitment,
				CommitB: *signed1Invalid,
			},
			true,
			"non valid commitment is not valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Invalid,
				CommitB: *signed1Commitment,
			},
			true,
			"non valid commitment not valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signedFailure1,
				CommitB: *signedFailure1,
			},
			true,
			"same failure indicating is not valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signedFailure1,
				CommitB: *signedFailure2,
			},
			false,
			"different failure indicating reason is valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Commitment,
				CommitB: *signed2Commitment,
			},
			true,
			"different signer is not valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Commitment,
				CommitB: *signed1Commitment2,
			},
			false,
			"valid evidence",
		},
		{
			EquivocationExecutorEvidence{
				CommitA: *signed1Commitment,
				CommitB: *signedFailure1,
			},
			false,
			"valid evidence",
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
