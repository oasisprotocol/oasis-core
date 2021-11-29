package commitment

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var nopSV = &nopSignatureVerifier{}

// nopSignatureVerifier is a no-op storage verifier.
type nopSignatureVerifier struct{}

func (n *nopSignatureVerifier) VerifyTxnSchedulerSigner(sig signature.Signature, round uint64) error {
	return nil
}

type staticSignatureVerifier struct {
	txnSchedulerPublicKey signature.PublicKey
}

func (n *staticSignatureVerifier) VerifyTxnSchedulerSigner(sig signature.Signature, round uint64) error {
	if !sig.PublicKey.Equal(n.txnSchedulerPublicKey) {
		return errors.New("unknown public key")
	}

	return nil
}

type staticNodeLookup struct {
	runtime *node.Runtime
}

func (n *staticNodeLookup) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	return &node.Node{
		Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:        id,
		Runtimes:  []*node.Runtime{n.runtime},
	}, nil
}

func TestPoolDefault(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a commitment.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	var id common.Namespace
	blk := block.NewGenesisBlock(id, 0)

	body := ComputeBody{
		Header: ComputeResultsHeader{
			Round:        blk.Header.Round,
			PreviousHash: blk.Header.PreviousHash,
			IORoot:       &blk.Header.IORoot,
			StateRoot:    &blk.Header.StateRoot,
		},
	}
	commit, err := SignExecutorCommitment(sk, id, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// An empty pool should work but should always error.
	pool := Pool{}
	err = pool.AddExecutorCommitment(context.Background(), blk, nopSV, &staticNodeLookup{}, commit, nil)
	require.Error(t, err, "AddExecutorCommitment")
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrNoCommittee, err)
	err = pool.CheckProposerTimeout(context.Background(), blk, nopSV, &staticNodeLookup{}, sk.Public(), 0)
	require.Error(t, err, "CheckProposerTimeout")
	require.Equal(t, ErrNoCommittee, err)
}

func TestPoolSingleCommitment(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a non-TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          rtID,
		Kind:        registry.KindCompute,
		TEEHardware: node.TEEHardwareInvalid,
		Executor: registry.ExecutorParameters{
			MaxMessages: 32,
		},
		GovernanceModel: registry.GovernanceEntity,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	committee := &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		Round:     0,
	}

	// Generate a commitment.
	childBlk, _, body := generateComputeBody(t, pool.Round)

	sv := &staticSignatureVerifier{}
	nl := &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
		},
	}

	// Test invalid commitments.
	for _, tc := range []struct {
		name        string
		fn          func(*ComputeBody)
		expectedErr error
	}{
		{"BlockBadRound", func(b *ComputeBody) { b.Header.Round-- }, ErrNotBasedOnCorrectBlock},
		{"BlockBadPreviousHash", func(b *ComputeBody) { b.Header.PreviousHash.FromBytes([]byte("invalid")) }, ErrNotBasedOnCorrectBlock},
		{"MissingIORootHash", func(b *ComputeBody) { b.Header.IORoot = nil }, ErrBadExecutorCommitment},
		{"MissingStateRootHash", func(b *ComputeBody) { b.Header.StateRoot = nil }, ErrBadExecutorCommitment},
		{"MissingMessagesHash", func(b *ComputeBody) { b.Header.MessagesHash = nil }, ErrBadExecutorCommitment},
		{"BadFailureIndicating", func(b *ComputeBody) { b.Failure = FailureUnknown }, ErrBadExecutorCommitment},
	} {
		_, _, invalidBody := generateComputeBody(t, pool.Round)

		tc.fn(&invalidBody)

		var commit *ExecutorCommitment
		commit, err = SignExecutorCommitment(sk, rtID, &invalidBody)
		require.NoError(t, err, "SignExecutorCommitment(%s)", tc.name)

		err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, commit, nil)
		require.Error(t, err, "AddExecutorCommitment(%s)", tc.name)
		require.Equal(t, tc.expectedErr, err, "AddExecutorCommitment(%s)", tc.name)
	}

	// Generate a valid commitment.
	commit, err := SignExecutorCommitment(sk, rtID, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// There should not be enough executor commitments.
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
	_, err = pool.ProcessCommitments(true)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

	// Test message validator function.
	bodyWithMsgs := body
	bodyWithMsgs.Messages = []message.Message{{Staking: &message.StakingMessage{Transfer: &staking.Transfer{}}}, {Registry: &message.RegistryMessage{UpdateRuntime: &registry.Runtime{}}}}
	msgHash := message.MessagesHash(bodyWithMsgs.Messages)
	bodyWithMsgs.Header.MessagesHash = &msgHash
	incorrectCommit, err := SignExecutorCommitment(sk, rtID, &bodyWithMsgs)
	require.NoError(t, err, "SignExecutorCommitment")

	errMsgVal := errors.New("message validation error")
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, incorrectCommit, func([]message.Message) error {
		return errMsgVal
	})
	require.Error(t, err, "AddExecutorCommitment should propagate message validator failure")
	require.Equal(t, errMsgVal, err, "AddExecutorCommitment should propagate message validator failure")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, commit, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, commit, nil)
	require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

	// There should be enough executor commitments and no discrepancy.
	dc, err := pool.ProcessCommitments(false)
	require.NoError(t, err, "ProcessCommitments")
	require.Equal(t, false, pool.Discrepancy)
	header := dc.ToDDResult().(*ComputeBody).Header
	require.EqualValues(t, &body.Header, &header, "DD should return the same header")
}

func TestPoolSingleCommitmentTEE(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:              rtID,
		Kind:            registry.KindCompute,
		TEEHardware:     node.TEEHardwareIntelSGX,
		GovernanceModel: registry.GovernanceEntity,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a dummy RAK.
	skRAK, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	committee := &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		Round:     0,
	}

	nl := &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
			Capabilities: node.Capabilities{
				TEE: &node.CapabilityTEE{
					Hardware:    node.TEEHardwareIntelSGX,
					RAK:         skRAK.Public(),
					Attestation: []byte("My RAK is my attestation. Verify me."),
				},
			},
		},
	}

	// Generate a commitment.
	childBlk, _, body := generateComputeBody(t, pool.Round)
	rakSig, err := signature.Sign(skRAK, ComputeResultsHeaderSignatureContext, cbor.Marshal(body.Header))
	require.NoError(t, err, "Sign")
	body.RakSig = &rakSig.Signature

	commit, err := SignExecutorCommitment(sk, rtID, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// There should not be enough executor commitments.
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
	_, err = pool.ProcessCommitments(true)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit, nil)
	require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

	// There should be enough executor commitments and no discrepancy.
	dc, err := pool.ProcessCommitments(false)
	require.NoError(t, err, "ProcessCommitments")
	require.Equal(t, false, pool.Discrepancy)
	header := dc.ToDDResult().(*ComputeBody).Header
	require.EqualValues(t, &body.Header, &header, "DD should return the same header")
}

func TestPoolStragglers(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks, committee, nl := generateMockCommittee(t, &registry.Runtime{
		Kind:        registry.KindCompute,
		TEEHardware: node.TEEHardwareInvalid,
		Executor: registry.ExecutorParameters{
			GroupSize:         2,
			GroupBackupSize:   1,
			AllowedStragglers: 1,
		},
		GovernanceModel: registry.GovernanceEntity,
	})
	sk1 := sks[0]
	sk2 := sks[1]

	t.Run("NonTxnSchedulerFirst", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, pool.Round)

		commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(sk2, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Add second commitment first as that one is not from the transaction scheduler.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
		_, err = pool.ProcessCommitments(true)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments and no discrepancy.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, false, pool.Discrepancy)
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &body.Header, &header, "DD should return the same header")
	})

	t.Run("TxnSchedulerFirst", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, pool.Round)

		commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Add first commitment first as that one is from the transaction scheduler.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments pre-timeout.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

		// There should be enough executor commitments after timeout (due to allowed stragglers)
		// and no discrepancy.
		dc, err := pool.ProcessCommitments(true)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, false, pool.Discrepancy)
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &body.Header, &header, "DD should return the same header")
	})
}

func TestPoolTwoCommitments(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks, committee, nl := generateMockCommittee(t, nil)
	sk1 := sks[0]
	sk2 := sks[1]
	sk3 := sks[2]

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, pool.Round)

		commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(sk2, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
		_, err = pool.ProcessCommitments(true)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments and no discrepancy.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, false, pool.Discrepancy)
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &body.Header, &header, "DD should return the same header")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		pool, childBlk, _, correctBody, _ := setupDiscrepancy(t, rt, sks, committee, nl, false)

		commit3, err := SignExecutorCommitment(sk3, rt.ID, correctBody)
		require.NoError(t, err, "SignExecutorCommitment")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments from backup workers and discrepancy
		// resolution should succeed.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &correctBody.Header, &header, "DR should return the same header")
	})

	t.Run("DiscrepancyResolutionFailureVotes", func(t *testing.T) {
		pool, _, _, _, _ := setupDiscrepancy(t, rt, sks, committee, nl, false)

		// Discrepancy resolution should fail.
		dc, err := pool.ProcessCommitments(true)
		require.Nil(t, dc, "ProcessCommitments")
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrInsufficientVotes, err)
	})

	t.Run("DiscrepancyResolutionFailureNotProposer", func(t *testing.T) {
		pool, childBlk, _, _, badBody := setupDiscrepancy(t, rt, sks, committee, nl, false)

		commit3, err := SignExecutorCommitment(sk3, rt.ID, badBody)
		require.NoError(t, err, "SignExecutorCommitment")

		// Resolve discrepancy with commit from backup worker. Use the BAD commit which is different
		// from what the proposer committed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments from backup workers discrepancy resolution
		// should fail.
		dc, err := pool.ProcessCommitments(false)
		require.Nil(t, dc, "ProcessCommitments")
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrBadProposerCommitment, err)
	})

	t.Run("DiscrepancyResolutionRoleOverlap", func(t *testing.T) {
		// Modify the committee so sk1 is both primary and backup.
		committee2 := &scheduler.Committee{
			Kind: scheduler.KindComputeExecutor,
			Members: []*scheduler.CommitteeNode{
				{
					Role:      scheduler.RoleWorker,
					PublicKey: sk1.Public(),
				},
				{
					Role:      scheduler.RoleWorker,
					PublicKey: sk2.Public(),
				},
				{
					Role:      scheduler.RoleBackupWorker,
					PublicKey: sk1.Public(),
				},
			},
		}

		pool, _, _, correctBody, _ := setupDiscrepancy(t, rt, sks, committee2, nl, true)

		// Backup worker commitment should not be needed for discrepancy resolution.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &correctBody.Header, &header, "DR should return the same header")
	})

	t.Run("EarlyDiscrepancyDetectionAndResolution", func(t *testing.T) {
		// Modify the committee so there are three primary workers and three backup workers.
		sk4, err := memorySigner.NewSigner(rand.Reader)
		require.NoError(t, err, "NewSigner")
		sk5, err := memorySigner.NewSigner(rand.Reader)
		require.NoError(t, err, "NewSigner")
		sk6, err := memorySigner.NewSigner(rand.Reader)
		require.NoError(t, err, "NewSigner")

		committee2 := &scheduler.Committee{
			Kind: scheduler.KindComputeExecutor,
			Members: []*scheduler.CommitteeNode{
				{
					Role:      scheduler.RoleWorker,
					PublicKey: sk1.Public(),
				},
				{
					Role:      scheduler.RoleWorker,
					PublicKey: sk2.Public(),
				},
				{
					Role:      scheduler.RoleWorker,
					PublicKey: sk3.Public(),
				},
				{
					Role:      scheduler.RoleBackupWorker,
					PublicKey: sk4.Public(),
				},
				{
					Role:      scheduler.RoleBackupWorker,
					PublicKey: sk5.Public(),
				},
				{
					Role:      scheduler.RoleBackupWorker,
					PublicKey: sk6.Public(),
				},
			},
		}

		// The setupDiscrepancy method will check whether a discrepancy was detected. This should
		// succeed despite there being a third worker in the committee which hasn't yet submitted
		// its own commitment.
		pool, childBlk, _, correctBody, _ := setupDiscrepancy(t, rt, sks, committee2, nl, true)

		// For discrepancy resolution, as soon as majority (two out of three) indicates a result,
		// the process should finish.
		commit4, err := SignExecutorCommitment(sk4, rt.ID, correctBody)
		require.NoError(t, err, "SignExecutorCommitment")
		commit5, err := SignExecutorCommitment(sk5, rt.ID, correctBody)
		require.NoError(t, err, "SignExecutorCommitment")

		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit4, nil)
		require.NoError(t, err, "AddExecutorCommitment")
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit5, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &correctBody.Header, &header, "DR should return the same header")
	})
}

func TestPoolFailureIndicatingCommitment(t *testing.T) {
	rt, sks, committee, nl := generateMockCommittee(t, nil)
	sk1 := sks[0]
	sk2 := sks[1]
	sk3 := sks[2]

	t.Run("FailureIndicating", func(t *testing.T) {
		genesisTestHelpers.SetTestChainContext()

		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		// Generate a compute body.
		childBlk, _, body := generateComputeBody(t, pool.Round)

		// Generate a valid commitment.
		commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		failedBody := ComputeBody{
			Header: ComputeResultsHeader{
				Round:        body.Header.Round,
				PreviousHash: body.Header.PreviousHash,
			},
			Failure: FailureUnknown,
		}
		commit2, err := SignExecutorCommitment(sk2, rt.ID, &failedBody)
		require.NoError(t, err, "SignExecutorCommitment")

		commit3, err := SignExecutorCommitment(sk3, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
		_, err = pool.ProcessCommitments(true)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

		// Adding a commitment should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// Adding a commitment twice for the same node should fail.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
		require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

		// Adding a failure indicating commitment.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough commitments and there should be a discrepancy.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)

		// There should not be enough executor commitments from backup workers.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments from backup workers and discrepancy
		// resolution should succeed.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &body.Header, &header, "DR should return the same header")
	})

	t.Run("DiscrepancyFailureIndicating", func(t *testing.T) {
		pool, childBlk, _, body, _ := setupDiscrepancy(t, rt, sks, committee, nl, false)
		body.SetFailure(FailureUnknown)

		commit3, err := SignExecutorCommitment(sk3, rt.ID, body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// Discrepancy resolution should fail with failure indicating commitment.
		dc, err := pool.ProcessCommitments(false)
		require.Nil(t, dc, "ProcessCommitments")
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrMajorityFailure, err)
	})
}

func TestPoolSerialization(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a non-TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		Versioned:       cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:              rtID,
		Kind:            registry.KindCompute,
		TEEHardware:     node.TEEHardwareInvalid,
		GovernanceModel: registry.GovernanceEntity,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	committee := &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		Round:     0,
	}

	nl := &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
		},
	}

	// Generate a commitment.
	childBlk, _, body := generateComputeBody(t, pool.Round)

	commit, err := SignExecutorCommitment(sk, rt.ID, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	m := cbor.Marshal(pool)
	var d Pool
	err = cbor.Unmarshal(m, &d)
	require.NoError(t, err)

	// There should be enough executor commitments and there should be no discrepancy.
	dc, err := pool.ProcessCommitments(false)
	require.NoError(t, err, "ProcessCommitments")
	require.Equal(t, false, pool.Discrepancy)
	header := dc.ToDDResult().(*ComputeBody).Header
	require.EqualValues(t, &body.Header, &header, "DD should return the same header")
}

func TestTryFinalize(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks, committee, nl := generateMockCommittee(t, nil)
	sk1 := sks[0]
	sk2 := sks[1]
	sk3 := sks[2]

	now := int64(1)
	roundTimeout := int64(10)

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, pool.Round)

		commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(sk2, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now+roundTimeout, pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &body.Header, &header, "DD should return the same header")
		require.EqualValues(t, TimeoutNever, pool.NextTimeout, "NextTimeout should be TimeoutNever")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		pool, childBlk, _, correctBody, _ := setupDiscrepancy(t, rt, sks, committee, nl, false)

		commit3, err := SignExecutorCommitment(sk3, rt.ID, correctBody)
		require.NoError(t, err, "SignExecutorCommitment")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &correctBody.Header, &header, "DR should return the same header")
		require.EqualValues(t, TimeoutNever, pool.NextTimeout, "NextTimeout should be TimeoutNever")
	})

	t.Run("Timeout", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, pool.Round)

		commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit3, err := SignExecutorCommitment(sk3, rt.ID, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		correctHeader := body.Header

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now+roundTimeout, pool.NextTimeout, "NextTimeout should be set")

		// Simulate a non-authoritative timeout -- this should return
		// a discrepancy detected error, but not change the internal
		// discrepancy flag.
		nowAfterTimeout := now + roundTimeout
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, true, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, false, pool.Discrepancy)
		require.EqualValues(t, TimeoutNever, pool.NextTimeout, "NextTimeout should be TimeoutNever")

		// Simulate a timeout -- this should cause a discrepancy.
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, true, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)
		require.EqualValues(t, nowAfterTimeout+(15*roundTimeout)/10, pool.NextTimeout, "NextTimeout should be set to 1.5*RoundTimeout")

		// There should not be enough executor commitments from backup workers.
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err)
		require.EqualValues(t, nowAfterTimeout+roundTimeout, pool.NextTimeout, "NextTimeout should be set")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		header := dc.ToDDResult().(*ComputeBody).Header
		require.EqualValues(t, &correctHeader, &header, "DR should return the same header")
		require.EqualValues(t, TimeoutNever, pool.NextTimeout, "NextTimeout should be TimeoutNever")
	})
}

func TestExecutorTimeoutRequest(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks, committee, nl := generateMockCommittee(t, nil)
	sk1 := sks[0]
	sk2 := sks[1]

	t.Run("ExecutorProposerTimeoutRequest", func(t *testing.T) {
		require := require.New(t)
		ctx := context.Background()

		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		var id common.Namespace
		childBlk := block.NewGenesisBlock(id, 0)

		type testCase struct {
			signer        signature.Signer
			round         uint64
			expectedError error
		}
		for _, tc := range []*testCase{
			// Scheduler (sk1 at round 0), is not allowed to request a timeout.
			{
				signer:        sk1,
				round:         0,
				expectedError: ErrNodeIsScheduler,
			},
			// Timeout round needs to match current round.
			{
				signer:        sk2,
				round:         100,
				expectedError: ErrTimeoutNotCorrectRound,
			},
			// Ok timeout request.
			{
				signer:        sk2,
				round:         0,
				expectedError: nil,
			},
		} {
			err := pool.CheckProposerTimeout(ctx, childBlk, nopSV, nl, tc.signer.Public(), tc.round)
			switch tc.expectedError {
			case nil:
				require.NoError(err, "CheckProposerTimeout unexpected error")
			default:
				require.Equal(tc.expectedError, err, "CheckProposerTimeout expected error")
			}
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, pool.Round)
		commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
		require.NoError(err, "SignExecutorCommitment")
		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(ctx, childBlk, nopSV, nl, commit1, nil)
		require.NoError(err, "AddExecutorCommitment")

		// Timeout after commitment should fail.
		err = pool.CheckProposerTimeout(ctx, childBlk, nopSV, nl, sk2.Public(), 0)
		require.Error(err, "CheckProposerTimeout commitment exists")
		require.Equal(ErrAlreadyCommitted, err, "CheckProposerTimeout commitment exists")
	})
}

func generateMockCommittee(t *testing.T, rtTemplate *registry.Runtime) (
	rt *registry.Runtime,
	sks []signature.Signer,
	committee *scheduler.Committee,
	nl NodeLookup,
) {
	switch rtTemplate {
	case nil:
		// Generate a default.
		rt = &registry.Runtime{
			Kind:        registry.KindCompute,
			TEEHardware: node.TEEHardwareInvalid,
			Executor: registry.ExecutorParameters{
				GroupSize:       2,
				GroupBackupSize: 1,
			},
			GovernanceModel: registry.GovernanceEntity,
		}
	default:
		// Use the provided runtime descriptor template.
		rt = rtTemplate
	}
	rt.Versioned = cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion)
	_ = rt.ID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	// Generate commitment signing keys.
	sk1, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	sk2, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	sk3, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	sks = append(sks, sk1, sk2, sk3)

	// Generate a committee.
	committee = &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk1.Public(),
			},
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk2.Public(),
			},
			{
				Role:      scheduler.RoleBackupWorker,
				PublicKey: sk3.Public(),
			},
		},
	}
	nl = &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rt.ID,
		},
	}

	return
}

func generateComputeBody(t *testing.T, round uint64) (*block.Block, *block.Block, ComputeBody) {
	var id common.Namespace
	childBlk := block.NewGenesisBlock(id, round)
	parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

	// TODO: Add tests with some emitted messages.
	msgsHash := message.MessagesHash(nil)

	body := ComputeBody{
		Header: ComputeResultsHeader{
			Round:        parentBlk.Header.Round,
			PreviousHash: parentBlk.Header.PreviousHash,
			IORoot:       &parentBlk.Header.IORoot,
			StateRoot:    &parentBlk.Header.StateRoot,
			MessagesHash: &msgsHash,
		},
	}

	return childBlk, parentBlk, body
}

func setupDiscrepancy(
	t *testing.T,
	rt *registry.Runtime,
	sks []signature.Signer,
	committee *scheduler.Committee,
	nl NodeLookup,
	enoughBackupCommits bool,
) (*Pool, *block.Block, *block.Block, *ComputeBody, *ComputeBody) {
	sk1 := sks[0]
	sk2 := sks[1]

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		Round:     0,
	}

	// Generate a commitment.
	childBlk, parentBlk, body := generateComputeBody(t, pool.Round)

	commit1, err := SignExecutorCommitment(sk1, rt.ID, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	correctBody := body

	// Update state root and fix the storage receipt.
	badHash := hash.NewFromBytes([]byte("discrepancy"))
	body.Header.StateRoot = &badHash

	commit2, err := SignExecutorCommitment(sk2, rt.ID, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// Adding commitment 1 should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	// There should not be enough executor commitments.
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
	_, err = pool.ProcessCommitments(true)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

	// Adding commitment 2 should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	// There should be enough executor commitments and there should be a discrepancy.
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrDiscrepancyDetected, err)
	require.Equal(t, true, pool.Discrepancy)

	if !enoughBackupCommits {
		// There should not be enough executor commitments from backup workers.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "there should not be enough commitments from backup workers")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
	}

	return &pool, childBlk, parentBlk, &correctBody, &body
}
