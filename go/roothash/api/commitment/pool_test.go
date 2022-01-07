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

	ec := ExecutorCommitment{
		NodeID: sk.Public(),
		Header: ExecutorCommitmentHeader{
			ComputeResultsHeader: ComputeResultsHeader{
				Round:        blk.Header.Round,
				PreviousHash: blk.Header.PreviousHash,
				IORoot:       &blk.Header.IORoot,
				StateRoot:    &blk.Header.StateRoot,
			},
		},
	}
	err = ec.Sign(sk, id)
	require.NoError(t, err, "ec.Sign")

	// An empty pool should work but should always error.
	pool := Pool{}
	err = pool.AddExecutorCommitment(context.Background(), blk, &staticNodeLookup{}, &ec, nil)
	require.Error(t, err, "AddExecutorCommitment")
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrNoCommittee, err)
	err = pool.CheckProposerTimeout(context.Background(), blk, &staticNodeLookup{}, sk.Public(), 0)
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
	childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

	nl := &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
		},
	}

	// Test invalid commitments.
	for _, tc := range []struct {
		name        string
		fn          func(*ExecutorCommitment)
		expectedErr error
	}{
		{"BlockBadRound", func(ec *ExecutorCommitment) { ec.Header.Round-- }, ErrNotBasedOnCorrectBlock},
		{"BlockBadPreviousHash", func(ec *ExecutorCommitment) { ec.Header.PreviousHash.FromBytes([]byte("invalid")) }, ErrNotBasedOnCorrectBlock},
		{"MissingIORootHash", func(ec *ExecutorCommitment) { ec.Header.IORoot = nil }, ErrBadExecutorCommitment},
		{"MissingStateRootHash", func(ec *ExecutorCommitment) { ec.Header.StateRoot = nil }, ErrBadExecutorCommitment},
		{"MissingMessagesHash", func(ec *ExecutorCommitment) { ec.Header.MessagesHash = nil }, ErrBadExecutorCommitment},
		{"MissingInMessagesHash", func(ec *ExecutorCommitment) { ec.Header.InMessagesHash = nil }, ErrBadExecutorCommitment},
		{"BadFailureIndicating", func(ec *ExecutorCommitment) { ec.Header.Failure = FailureUnknown }, ErrBadExecutorCommitment},
	} {
		_, _, invalidEc := generateExecutorCommitment(t, pool.Round)

		tc.fn(&invalidEc)

		invalidEc.NodeID = sk.Public()
		err = invalidEc.Sign(sk, rtID)
		require.NoError(t, err, "invalidEc.Sign(%s)", tc.name)

		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &invalidEc, nil)
		require.Error(t, err, "AddExecutorCommitment(%s)", tc.name)
		require.Equal(t, tc.expectedErr, err, "AddExecutorCommitment(%s)", tc.name)
	}

	// Generate a valid commitment.
	ec.NodeID = sk.Public()
	err = ec.Sign(sk, rtID)
	require.NoError(t, err, "ec.Sign")

	// There should not be enough executor commitments.
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
	_, err = pool.ProcessCommitments(true)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

	// Test message validator function.
	ecWithMsgs := ec
	ecWithMsgs.Messages = []message.Message{
		{Staking: &message.StakingMessage{Transfer: &staking.Transfer{}}},
		{Registry: &message.RegistryMessage{UpdateRuntime: &registry.Runtime{}}},
	}
	msgHash := message.MessagesHash(ecWithMsgs.Messages)
	ecWithMsgs.Header.MessagesHash = &msgHash
	err = ecWithMsgs.Sign(sk, rtID)
	require.NoError(t, err, "ecWithMsgs.Sign")

	errMsgVal := errors.New("message validation error")
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ecWithMsgs, func([]message.Message) error {
		return errMsgVal
	})
	require.Error(t, err, "AddExecutorCommitment should propagate message validator failure")
	require.Equal(t, errMsgVal, err, "AddExecutorCommitment should propagate message validator failure")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec, nil)
	require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

	// There should be enough executor commitments and no discrepancy.
	dc, err := pool.ProcessCommitments(false)
	require.NoError(t, err, "ProcessCommitments")
	require.Equal(t, false, pool.Discrepancy)
	ddEc := dc.ToDDResult().(*ExecutorCommitment)
	require.EqualValues(t, &ec, ddEc, "DD should return the correct commitment")
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
	childBlk, _, ec := generateExecutorCommitment(t, pool.Round)
	rakSig, err := signature.Sign(skRAK, ComputeResultsHeaderSignatureContext, cbor.Marshal(ec.Header.ComputeResultsHeader))
	require.NoError(t, err, "Sign")
	ec.Header.RAKSignature = &rakSig.Signature

	ec.NodeID = sk.Public()
	err = ec.Sign(sk, rtID)
	require.NoError(t, err, "ec.Sign")

	// There should not be enough executor commitments.
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
	_, err = pool.ProcessCommitments(true)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec, nil)
	require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

	// There should be enough executor commitments and no discrepancy.
	dc, err := pool.ProcessCommitments(false)
	require.NoError(t, err, "ProcessCommitments")
	require.Equal(t, false, pool.Discrepancy)
	ddEc := dc.ToDDResult().(*ExecutorCommitment)
	require.EqualValues(t, &ec, ddEc, "DD should return the correct commitment")
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
		childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

		ec1 := ec
		ec1.NodeID = sk1.Public()
		err := ec1.Sign(sk1, rt.ID)
		require.NoError(t, err, "ec1.Sign")

		ec2 := ec
		ec2.NodeID = sk2.Public()
		err = ec2.Sign(sk2, rt.ID)
		require.NoError(t, err, "ec2.Sign")

		// Add second commitment first as that one is not from the transaction scheduler.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec2, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
		_, err = pool.ProcessCommitments(true)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments and no discrepancy.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, false, pool.Discrepancy)
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, &ec1, ddEc, "DD should return the correct commitment")
	})

	t.Run("TxnSchedulerFirst", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			Round:     0,
		}

		// Generate a commitment.
		childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

		ec.NodeID = sk1.Public()
		err := ec.Sign(sk1, rt.ID)
		require.NoError(t, err, "ec.Sign")

		// Add first commitment first as that one is from the transaction scheduler.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec, nil)
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
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, &ec, ddEc, "DD should return the correct commitment")
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
		childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

		ec1 := ec
		ec1.NodeID = sk1.Public()
		err := ec1.Sign(sk1, rt.ID)
		require.NoError(t, err, "ec1.Sign")

		ec2 := ec
		ec2.NodeID = sk2.Public()
		err = ec2.Sign(sk2, rt.ID)
		require.NoError(t, err, "ec2.Sign")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
		_, err = pool.ProcessCommitments(true)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec2, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments and no discrepancy.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, false, pool.Discrepancy)
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, &ec1, ddEc, "DD should return the correct commitment")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		pool, childBlk, _, correctEc, _ := setupDiscrepancy(t, rt, sks, committee, nl, false)

		ec3 := *correctEc
		ec3.NodeID = sk3.Public()
		err := ec3.Sign(sk3, rt.ID)
		require.NoError(t, err, "ec3.Sign")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments from backup workers and discrepancy
		// resolution should succeed.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, correctEc, ddEc, "DR should return the correct commitment")
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
		pool, childBlk, _, _, badEc := setupDiscrepancy(t, rt, sks, committee, nl, false)

		ec3 := *badEc
		ec3.NodeID = sk3.Public()
		err := ec3.Sign(sk3, rt.ID)
		require.NoError(t, err, "ec3.Sign")

		// Resolve discrepancy with commit from backup worker. Use the BAD commit which is different
		// from what the proposer committed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec3, nil)
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

		pool, _, _, correctEc, _ := setupDiscrepancy(t, rt, sks, committee2, nl, true)

		// Backup worker commitment should not be needed for discrepancy resolution.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, correctEc, ddEc, "DR should return the correct commitment")
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
		pool, childBlk, _, correctEc, _ := setupDiscrepancy(t, rt, sks, committee2, nl, true)

		// For discrepancy resolution, as soon as majority (two out of three) indicates a result,
		// the process should finish.
		ec4 := *correctEc
		ec4.NodeID = sk4.Public()
		err = ec4.Sign(sk4, rt.ID)
		require.NoError(t, err, "ec4.Sign")

		ec5 := *correctEc
		ec5.NodeID = sk5.Public()
		err = ec5.Sign(sk5, rt.ID)
		require.NoError(t, err, "ec5.Sign")

		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec4, nil)
		require.NoError(t, err, "AddExecutorCommitment")
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec5, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, correctEc, ddEc, "DR should return the correct commitment")
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

		// Generate an executor commitment.
		childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

		// Generate a valid commitment.
		ec1 := ec
		ec1.NodeID = sk1.Public()
		err := ec1.Sign(sk1, rt.ID)
		require.NoError(t, err, "ec1.Sign")

		failedEc := ExecutorCommitment{
			NodeID: sk2.Public(),
			Header: ExecutorCommitmentHeader{
				ComputeResultsHeader: ComputeResultsHeader{
					Round:        ec.Header.Round,
					PreviousHash: ec.Header.PreviousHash,
				},
				Failure: FailureUnknown,
			},
		}
		err = failedEc.Sign(sk2, rt.ID)
		require.NoError(t, err, "failedEc.Sign")

		ec3 := ec
		ec3.NodeID = sk3.Public()
		err = ec3.Sign(sk3, rt.ID)
		require.NoError(t, err, "ec3.Sign")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
		_, err = pool.ProcessCommitments(true)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrNoProposerCommitment, err, "ProcessCommitments")

		// Adding a commitment should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// Adding a commitment twice for the same node should fail.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec1, nil)
		require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

		// There should not be enough executor commitments.
		_, err = pool.ProcessCommitments(false)
		require.Error(t, err, "ProcessCommitments")
		require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

		// Adding a failure indicating commitment.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &failedEc, nil)
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
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments from backup workers and discrepancy
		// resolution should succeed.
		dc, err := pool.ProcessCommitments(false)
		require.NoError(t, err, "ProcessCommitments")
		require.Equal(t, true, pool.Discrepancy)
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, &ec1, ddEc, "DR should return the correct commitment")
	})

	t.Run("DiscrepancyFailureIndicating", func(t *testing.T) {
		pool, childBlk, _, ec3, _ := setupDiscrepancy(t, rt, sks, committee, nl, false)
		ec3.Header.SetFailure(FailureUnknown)

		ec3.NodeID = sk3.Public()
		err := ec3.Sign(sk3, rt.ID)
		require.NoError(t, err, "SignExecutorCommitment")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, ec3, nil)
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
	childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

	ec.NodeID = sk.Public()
	err = ec.Sign(sk, rt.ID)
	require.NoError(t, err, "ec.Sign")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	m := cbor.Marshal(pool)
	var d Pool
	err = cbor.Unmarshal(m, &d)
	require.NoError(t, err)

	// There should be enough executor commitments and there should be no discrepancy.
	dc, err := pool.ProcessCommitments(false)
	require.NoError(t, err, "ProcessCommitments")
	require.Equal(t, false, pool.Discrepancy)
	ddEc := dc.ToDDResult().(*ExecutorCommitment)
	require.EqualValues(t, &ec, ddEc, "DD should return the correct commitment")
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
		childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

		ec1 := ec
		ec1.NodeID = sk1.Public()
		err := ec1.Sign(sk1, rt.ID)
		require.NoError(t, err, "ec1.Sign")

		ec2 := ec
		ec2.NodeID = sk2.Public()
		err = ec2.Sign(sk2, rt.ID)
		require.NoError(t, err, "ec2.Sign")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec1, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now+roundTimeout, pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec2, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, &ec1, ddEc, "DD should return the correct commitment")
		require.EqualValues(t, TimeoutNever, pool.NextTimeout, "NextTimeout should be TimeoutNever")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		pool, childBlk, _, correctEc, _ := setupDiscrepancy(t, rt, sks, committee, nl, false)

		ec3 := *correctEc
		ec3.NodeID = sk3.Public()
		err := ec3.Sign(sk3, rt.ID)
		require.NoError(t, err, "ec3.Sign")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, correctEc, ddEc, "DR should return the correct commitment")
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
		childBlk, _, ec := generateExecutorCommitment(t, pool.Round)

		ec1 := ec
		ec1.NodeID = sk1.Public()
		err := ec1.Sign(sk1, rt.ID)
		require.NoError(t, err, "ec1.Sign")

		ec3 := ec
		ec3.NodeID = sk3.Public()
		err = ec3.Sign(sk3, rt.ID)
		require.NoError(t, err, "ec3.Sign")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec1, nil)
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
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec3, nil)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		ddEc := dc.ToDDResult().(*ExecutorCommitment)
		require.EqualValues(t, &ec1, ddEc, "DR should return the correct commitment")
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
			err := pool.CheckProposerTimeout(ctx, childBlk, nl, tc.signer.Public(), tc.round)
			switch tc.expectedError {
			case nil:
				require.NoError(err, "CheckProposerTimeout unexpected error")
			default:
				require.Equal(tc.expectedError, err, "CheckProposerTimeout expected error")
			}
		}

		// Generate a commitment.
		childBlk, _, ec := generateExecutorCommitment(t, pool.Round)
		ec.NodeID = sk1.Public()
		err := ec.Sign(sk1, rt.ID)
		require.NoError(err, "ec.Sign")
		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(ctx, childBlk, nl, &ec, nil)
		require.NoError(err, "AddExecutorCommitment")

		// Timeout after commitment should fail.
		err = pool.CheckProposerTimeout(ctx, childBlk, nl, sk2.Public(), 0)
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

func generateExecutorCommitment(t *testing.T, round uint64) (*block.Block, *block.Block, ExecutorCommitment) {
	var id common.Namespace
	childBlk := block.NewGenesisBlock(id, round)
	parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

	// TODO: Add tests with some emitted messages.
	msgsHash := message.MessagesHash(nil)
	// TODO: Add tests with some incoming messages.
	inMsgsHash := message.InMessagesHash(nil)

	ec := ExecutorCommitment{
		Header: ExecutorCommitmentHeader{
			ComputeResultsHeader: ComputeResultsHeader{
				Round:          parentBlk.Header.Round,
				PreviousHash:   parentBlk.Header.PreviousHash,
				IORoot:         &parentBlk.Header.IORoot,
				StateRoot:      &parentBlk.Header.StateRoot,
				MessagesHash:   &msgsHash,
				InMessagesHash: &inMsgsHash,
			},
		},
	}

	return childBlk, parentBlk, ec
}

func setupDiscrepancy(
	t *testing.T,
	rt *registry.Runtime,
	sks []signature.Signer,
	committee *scheduler.Committee,
	nl NodeLookup,
	enoughBackupCommits bool,
) (*Pool, *block.Block, *block.Block, *ExecutorCommitment, *ExecutorCommitment) {
	sk1 := sks[0]
	sk2 := sks[1]

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		Round:     0,
	}

	// Generate a commitment.
	childBlk, parentBlk, ec := generateExecutorCommitment(t, pool.Round)

	ec1 := ec
	ec1.NodeID = sk1.Public()
	err := ec1.Sign(sk1, rt.ID)
	require.NoError(t, err, "ec1.Sign")

	// Update state root.
	ec2 := ec
	ec2.NodeID = sk2.Public()
	badHash := hash.NewFromBytes([]byte("discrepancy"))
	ec2.Header.StateRoot = &badHash

	err = ec2.Sign(sk2, rt.ID)
	require.NoError(t, err, "ec2.Sign")

	// Adding commitment 1 should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec1, nil)
	require.NoError(t, err, "AddExecutorCommitment")

	// There should not be enough executor commitments.
	_, err = pool.ProcessCommitments(false)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")
	_, err = pool.ProcessCommitments(true)
	require.Error(t, err, "ProcessCommitments")
	require.Equal(t, ErrStillWaiting, err, "ProcessCommitments")

	// Adding commitment 2 should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nl, &ec2, nil)
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

	return &pool, childBlk, parentBlk, &ec1, &ec2
}
