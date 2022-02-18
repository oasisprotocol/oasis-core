package roothash

import (
	"crypto/rand"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

type testMsgDispatcher struct{}

// Implements MessageDispatcher.
func (nd *testMsgDispatcher) Subscribe(interface{}, abciAPI.MessageSubscriber) {
}

// Implements MessageDispatcher.
func (nd *testMsgDispatcher) Publish(ctx *abciAPI.Context, kind, msg interface{}) (interface{}, error) {
	// Either we need to be in simulation mode or the gas accountant must be a no-op one.
	if !ctx.IsSimulation() && ctx.Gas() != abciAPI.NewNopGasAccountant() {
		panic("gas estimation should always use simulation mode")
	}

	gasCosts := transaction.Costs{
		staking.GasOpTransfer:         1000,
		staking.GasOpWithdraw:         2000,
		staking.GasOpAddEscrow:        2000,
		staking.GasOpReclaimEscrow:    2000,
		registry.GasOpRegisterRuntime: 3000,
	}

	switch kind {
	case roothashApi.RuntimeMessageStaking:
		m := msg.(*message.StakingMessage)
		switch {
		case m.Transfer != nil:
			if err := ctx.Gas().UseGas(1, staking.GasOpTransfer, gasCosts); err != nil {
				return nil, err
			}
			return nil, nil
		case m.Withdraw != nil:
			if err := ctx.Gas().UseGas(1, staking.GasOpWithdraw, gasCosts); err != nil {
				return nil, err
			}
			return nil, nil
		case m.AddEscrow != nil:
			if err := ctx.Gas().UseGas(1, staking.GasOpAddEscrow, gasCosts); err != nil {
				return nil, err
			}
			return nil, nil
		case m.ReclaimEscrow != nil:
			if err := ctx.Gas().UseGas(1, staking.GasOpReclaimEscrow, gasCosts); err != nil {
				return nil, err
			}
			return nil, nil
		default:
			return nil, staking.ErrInvalidArgument
		}
	case roothashApi.RuntimeMessageRegistry:
		m := msg.(*message.RegistryMessage)
		switch {
		case m.UpdateRuntime != nil:
			if err := ctx.Gas().UseGas(1, registry.GasOpRegisterRuntime, gasCosts); err != nil {
				return nil, err
			}
			return nil, nil
		default:
			return nil, registry.ErrInvalidArgument
		}
	default:
		return nil, staking.ErrInvalidArgument
	}
}

func TestMessagesGasEstimation(t *testing.T) {
	require := require.New(t)
	var err error

	genesisTestHelpers.SetTestChainContext()

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Configure the maximum amount of gas.
	ctx.SetGasAccountant(abciAPI.NewGasAccountant(transaction.Gas(math.MaxUint64)))

	// Create a test message dispatcher that fakes gas estimation.
	var md testMsgDispatcher
	app := rootHashApplication{appState, &md}

	// Generate a private key for the single node in this test.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	// Initialize registry state.
	runtime := registry.Runtime{
		Executor: registry.ExecutorParameters{
			MaxMessages: 32,
		},
	}

	// Initialize scheduler state.
	schedulerState := schedulerState.NewMutableState(ctx.State())
	executorCommittee := scheduler.Committee{
		RuntimeID: runtime.ID,
		Kind:      scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}
	err = schedulerState.PutCommittee(ctx, &executorCommittee)
	require.NoError(err, "PutCommittee")

	// Initialize roothash state.
	roothashState := roothashState.NewMutableState(ctx.State())
	err = roothashState.SetConsensusParameters(ctx, &roothash.ConsensusParameters{
		MaxRuntimeMessages: 32,
	})
	require.NoError(err, "SetConsensusParameters")
	blk := block.NewGenesisBlock(runtime.ID, 0)
	err = roothashState.SetRuntimeState(ctx, &roothash.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1,
		LastNormalRound:    0,
		LastNormalHeight:   1,
		ExecutorPool: &commitment.Pool{
			Runtime:   &runtime,
			Committee: &executorCommittee,
			Round:     0,
		},
	})
	require.NoError(err, "SetRuntimeState")

	// Generate executor commitment for a new block.
	newBlk := block.NewEmptyBlock(blk, 1, block.Normal)

	msgs := []message.Message{
		// Each transfer message costs 1000 gas.
		{Staking: &message.StakingMessage{Transfer: &staking.Transfer{}}},
		{Staking: &message.StakingMessage{Transfer: &staking.Transfer{}}},
		{Staking: &message.StakingMessage{Transfer: &staking.Transfer{}}},
		// Each withdraw message costs 2000 gas.
		{Staking: &message.StakingMessage{Withdraw: &staking.Withdraw{}}},
		// Each add escrow message costs 2000 gas.
		{Staking: &message.StakingMessage{AddEscrow: &staking.Escrow{}}},
		// Each reclaim escrow message costs 2000 gas.
		{Staking: &message.StakingMessage{ReclaimEscrow: &staking.ReclaimEscrow{}}},
		// Each update_runtime message costs 3000 gas.
		{Registry: &message.RegistryMessage{UpdateRuntime: &registry.Runtime{}}},
	}
	msgsHash := message.MessagesHash(msgs)

	var emptyHash hash.Hash
	emptyHash.Empty()

	ec := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          newBlk.Header.Round,
				PreviousHash:   newBlk.Header.PreviousHash,
				IORoot:         &newBlk.Header.IORoot,
				StateRoot:      &newBlk.Header.StateRoot,
				MessagesHash:   &msgsHash,
				InMessagesHash: &emptyHash,
			},
		},
		Messages: msgs,
	}

	err = ec.Sign(sk, runtime.ID)
	require.NoError(err, "ec.Sign")

	// Generate executor commit transaction body.
	cc := &roothash.ExecutorCommit{
		ID:      runtime.ID,
		Commits: []commitment.ExecutorCommitment{ec},
	}

	err = app.executorCommit(ctx, roothashState, cc)
	require.NoError(err, "ExecutorCommit")
	require.EqualValues(12000, ctx.Gas().GasUsed(), "gas amount should be correct")
}

func TestEvidence(t *testing.T) {
	require := require.New(t)
	var err error

	genesisTestHelpers.SetTestChainContext()

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Generate a private key for the node in this test.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	// Signer for a non-existing node.
	nonExistingSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	entitySigner := memorySigner.NewTestSigner("consensus/tendermint/apps/roothash: entity signer")

	// Initialize staking state.
	stakingState := stakingState.NewMutableState(ctx.State())
	err = stakingState.SetConsensusParameters(ctx, &staking.ConsensusParameters{})
	require.NoError(err, "staking.SetConsensusParameters")
	entityEscrow := quantity.NewFromUint64(100)
	entityAccount := staking.Account{
		General: staking.GeneralAccount{
			Balance: quantity.Quantity{},
		},
		Escrow: staking.EscrowAccount{
			Active: staking.SharePool{
				Balance:     *entityEscrow,
				TotalShares: *quantity.NewFromUint64(100),
			},
		},
	}
	err = stakingState.SetAccount(ctx, staking.NewAddress(entitySigner.Public()), &entityAccount)
	require.NoError(err, "SetAccount")

	// Initialize registry state.
	registryState := registryState.NewMutableState(ctx.State())

	nod := &node.Node{
		Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:        sk.Public(),
		Consensus: node.ConsensusInfo{ID: sk.Public()},
		EntityID:  entitySigner.Public(),
	}
	sigNode, nErr := node.MultiSignNode([]signature.Signer{sk}, registry.RegisterNodeSignatureContext, nod)
	require.NoError(nErr, "MultiSignNode")
	err = registryState.SetNode(ctx, nil, nod, sigNode)
	require.NoError(err, "SetNode")

	// Initialize runtimes.
	uninitializedRtID := common.NewTestNamespaceFromSeed([]byte("tendermint/apps/roothash/transaction_test: non existing runtime"), 0)
	slashAmount := quantity.NewFromUint64(40)
	runtime := registry.Runtime{
		Executor: registry.ExecutorParameters{
			MaxMessages: 32,
		},

		Staking: registry.RuntimeStakingParameters{
			Slashing: map[staking.SlashReason]staking.Slash{
				staking.SlashRuntimeEquivocation: {Amount: *slashAmount},
			},
		},
	}
	runtimeNoSlashing := registry.Runtime{
		ID: common.NewTestNamespaceFromSeed([]byte("tendermint/apps/roothash/transaction_test: runtime no slashing"), 0),
	}
	runtimeZeroSlashing := registry.Runtime{
		ID: common.NewTestNamespaceFromSeed([]byte("tendermint/apps/roothash/transaction_test: runtime zero slashing"), 0),
		Staking: registry.RuntimeStakingParameters{
			Slashing: map[staking.SlashReason]staking.Slash{
				staking.SlashRuntimeEquivocation: {},
			},
		},
	}

	// Initialize scheduler state.
	schedulerState := schedulerState.NewMutableState(ctx.State())
	executorCommittee := scheduler.Committee{
		RuntimeID: runtime.ID,
		Kind:      scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}
	err = schedulerState.PutCommittee(ctx, &executorCommittee)
	require.NoError(err, "PutCommittee")

	// Initialize roothash state.
	roothashState := roothashState.NewMutableState(ctx.State())
	err = roothashState.SetConsensusParameters(ctx, &roothash.ConsensusParameters{
		MaxRuntimeMessages: 32,
		MaxEvidenceAge:     50,
	})
	require.NoError(err, "SetConsensusParameters")
	blk := block.NewGenesisBlock(runtime.ID, 0)
	blk.Header.Round = 99
	err = roothashState.SetRuntimeState(ctx, &roothash.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1000,
		LastNormalRound:    99,
		LastNormalHeight:   1000,
		ExecutorPool: &commitment.Pool{
			Runtime:   &runtime,
			Committee: &executorCommittee,
			Round:     99,
		},
	})
	require.NoError(err, "SetRuntimeState")
	err = roothashState.SetRuntimeState(ctx, &roothash.RuntimeState{
		Runtime:            &runtimeNoSlashing,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1000,
		LastNormalRound:    99,
		LastNormalHeight:   1000,
		ExecutorPool: &commitment.Pool{
			Runtime:   &runtime,
			Committee: &executorCommittee,
			Round:     99,
		},
	})
	require.NoError(err, "SetRuntimeState")
	err = roothashState.SetRuntimeState(ctx, &roothash.RuntimeState{
		Runtime:            &runtimeZeroSlashing,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1000,
		LastNormalRound:    99,
		LastNormalHeight:   1000,
		ExecutorPool: &commitment.Pool{
			Runtime:   &runtime,
			Committee: &executorCommittee,
			Round:     99,
		},
	})
	require.NoError(err, "SetRuntimeState")

	// Initialize evidence.
	blk2 := block.NewEmptyBlock(blk, 0, block.Normal)

	// Proposed batch.
	signedBatch1 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        blk2.Header.Round,
			PreviousHash: blk2.Header.PreviousHash,
			BatchHash:    blk2.Header.IORoot,
		},
	}
	err = signedBatch1.Sign(sk, runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")
	noSlashingRtB1 := signedBatch1
	err = noSlashingRtB1.Sign(sk, runtimeNoSlashing.ID)
	require.NoError(err, "ProposalHeader.Sign")
	zeroSlashingRtB1 := signedBatch1
	err = zeroSlashingRtB1.Sign(sk, runtimeZeroSlashing.ID)
	require.NoError(err, "ProposalHeader.Sign")
	nonExistingSignerBatch1 := signedBatch1
	nonExistingSignerBatch1.NodeID = nonExistingSigner.Public()
	err = nonExistingSignerBatch1.Sign(nonExistingSigner, runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")
	uninitializedRtB1 := signedBatch1
	err = uninitializedRtB1.Sign(sk, uninitializedRtID)
	require.NoError(err, "ProposalHeader.Sign")

	signedBatch2 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        blk2.Header.Round,
			PreviousHash: blk2.Header.PreviousHash,
			BatchHash:    hash.NewFromBytes([]byte("invalid root")),
		},
	}
	err = signedBatch2.Sign(sk, runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")
	noSlashingRtB2 := signedBatch2
	err = noSlashingRtB2.Sign(sk, runtimeNoSlashing.ID)
	require.NoError(err, "ProposalHeader.Sign")
	zeroSlashingRtB2 := signedBatch2
	err = zeroSlashingRtB2.Sign(sk, runtimeZeroSlashing.ID)
	require.NoError(err, "ProposalHeader.Sign")
	nonExistingSignerBatch2 := signedBatch2
	nonExistingSignerBatch2.NodeID = nonExistingSigner.Public()
	err = nonExistingSignerBatch2.Sign(nonExistingSigner, runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")
	uninitializedRtB2 := signedBatch2
	err = uninitializedRtB2.Sign(sk, uninitializedRtID)
	require.NoError(err, "ProposalHeader.Sign")

	var emptyHash hash.Hash
	emptyHash.Empty()

	// Executor commit.
	signedCommitment1 := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          blk.Header.Round,
				PreviousHash:   blk.Header.PreviousHash,
				IORoot:         &blk.Header.IORoot,
				StateRoot:      &blk.Header.StateRoot,
				MessagesHash:   &emptyHash,
				InMessagesHash: &emptyHash,
			},
		},
	}
	err = signedCommitment1.Sign(sk, runtime.ID)
	require.NoError(err, "signedCommitment1.Sign")
	signedCommitment2 := signedCommitment1
	signedCommitment2.Header.PreviousHash = hash.NewFromBytes([]byte("invalid ioroot"))
	err = signedCommitment2.Sign(sk, runtime.ID)
	require.NoError(err, "signedCommitment2.Sign")

	// Expired evidence.
	blk2.Header.Round = 25
	expiredB1 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        blk2.Header.Round,
			PreviousHash: blk2.Header.PreviousHash,
			BatchHash:    blk2.Header.IORoot,
		},
	}
	err = expiredB1.Sign(sk, runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")
	expiredB2 := commitment.Proposal{
		NodeID: sk.Public(),
		Header: commitment.ProposalHeader{
			Round:        blk2.Header.Round,
			PreviousHash: blk2.Header.PreviousHash,
			BatchHash:    hash.NewFromBytes([]byte("invalid root")),
		},
	}
	err = expiredB2.Sign(sk, runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")

	expiredCommitment1 := commitment.ExecutorCommitment{
		NodeID: sk.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			ComputeResultsHeader: commitment.ComputeResultsHeader{
				Round:          blk2.Header.Round,
				PreviousHash:   blk2.Header.PreviousHash,
				IORoot:         &blk2.Header.IORoot,
				StateRoot:      &blk2.Header.StateRoot,
				MessagesHash:   &emptyHash,
				InMessagesHash: &emptyHash,
			},
		},
	}
	err = expiredCommitment1.Sign(sk, runtime.ID)
	require.NoError(err, "expiredCommitment1.Sign")
	expiredCommitment2 := expiredCommitment1
	expiredCommitment2.Header.PreviousHash = hash.NewFromBytes([]byte("invalid ioroot"))
	err = expiredCommitment2.Sign(sk, runtime.ID)
	require.NoError(err, "expiredCommitment2.Sign")
	var md testMsgDispatcher
	app := rootHashApplication{appState, &md}

	ctx = appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	for _, ev := range []struct {
		ev  *roothash.Evidence
		err error
		msg string
	}{
		{
			&roothash.Evidence{},
			roothash.ErrInvalidEvidence,
			"invalid evidence",
		},
		{
			&roothash.Evidence{
				ID: runtimeNoSlashing.ID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: signedBatch1,
					ProposalB: signedBatch2,
				},
			},
			roothash.ErrInvalidEvidence,
			"invalid evidence (signed batch runtime does not match evidence runtime)",
		},
		{
			&roothash.Evidence{
				ID: runtimeNoSlashing.ID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: noSlashingRtB1,
					ProposalB: noSlashingRtB2,
				},
			},
			roothash.ErrRuntimeDoesNotSlash,
			"evidence for runtime without slashing",
		},
		{
			&roothash.Evidence{
				ID: runtimeZeroSlashing.ID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: zeroSlashingRtB1,
					ProposalB: zeroSlashingRtB2,
				},
			},
			roothash.ErrRuntimeDoesNotSlash,
			"evidence for runtime with zero slashing",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationExecutor: &roothash.EquivocationExecutorEvidence{
					CommitA: expiredCommitment1,
					CommitB: expiredCommitment2,
				},
			},
			roothash.ErrInvalidEvidence,
			"expired executor evidence",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: expiredB1,
					ProposalB: expiredB2,
				},
			},
			roothash.ErrInvalidEvidence,
			"expired batch evidence",
		},
		{
			&roothash.Evidence{
				ID: uninitializedRtID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: uninitializedRtB1,
					ProposalB: uninitializedRtB2,
				},
			},
			roothash.ErrInvalidRuntime,
			"evidence for nonexisting runtime",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationExecutor: &roothash.EquivocationExecutorEvidence{
					CommitA: signedCommitment1,
					CommitB: signedCommitment2,
				},
			},
			nil,
			"valid executor evidence",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: signedBatch1,
					ProposalB: signedBatch2,
				},
			},
			nil,
			"valid batch evidence",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: signedBatch1,
					ProposalB: signedBatch2,
				},
			},
			roothash.ErrDuplicateEvidence,
			"duplicate evidence",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationProposal: &roothash.EquivocationProposalEvidence{
					ProposalA: nonExistingSignerBatch1,
					ProposalB: nonExistingSignerBatch2,
				},
			},
			roothash.ErrInvalidEvidence,
			"evidence for non-existing node",
		},
	} {
		err = app.submitEvidence(ctx, roothashState, ev.ev)
		require.ErrorIs(err, ev.err, ev.msg)
	}

	// Check that expected amount was slashed.
	// Entity should be slashed two times.
	require.NoError(entityEscrow.Sub(slashAmount))
	require.NoError(entityEscrow.Sub(slashAmount))

	entAcc, err := stakingState.Account(ctx, staking.NewAddress(nod.EntityID))
	require.NoError(err, "Account()")
	require.EqualValues(entityEscrow, &entAcc.Escrow.Active.Balance, "entity was slashed expected amount")
}

func TestSubmitMsg(t *testing.T) {
	require := require.New(t)
	var err error

	genesisTestHelpers.SetTestChainContext()

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	var md testMsgDispatcher
	app := rootHashApplication{appState, &md}

	// Generate a private key for the caller.
	skCaller, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")
	callerAddress := staking.NewAddress(skCaller.Public())
	ctx = ctx.WithCallerAddress(callerAddress)

	// Generate a private key for the single node in this test.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	// Initialize registry state.
	runtime := registry.Runtime{
		Executor: registry.ExecutorParameters{
			MaxMessages: 32,
		},
	}

	// Initialize staking state.
	stakingState := stakingState.NewMutableState(ctx.State())
	err = stakingState.SetConsensusParameters(ctx, &staking.ConsensusParameters{})
	require.NoError(err, "staking SetConsensusParameters")

	// Initialize scheduler state.
	schedulerState := schedulerState.NewMutableState(ctx.State())
	executorCommittee := scheduler.Committee{
		RuntimeID: runtime.ID,
		Kind:      scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}
	err = schedulerState.PutCommittee(ctx, &executorCommittee)
	require.NoError(err, "PutCommittee")

	// Initialize roothash state.
	roothashState := roothashState.NewMutableState(ctx.State())
	err = roothashState.SetConsensusParameters(ctx, &roothash.ConsensusParameters{
		MaxRuntimeMessages: 32,
	})
	require.NoError(err, "SetConsensusParameters")
	blk := block.NewGenesisBlock(runtime.ID, 0)
	rtState := roothash.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1,
		LastNormalRound:    0,
		LastNormalHeight:   1,
		ExecutorPool: &commitment.Pool{
			Runtime:   &runtime,
			Committee: &executorCommittee,
			Round:     0,
		},
	}
	err = roothashState.SetRuntimeState(ctx, &rtState)
	require.NoError(err, "SetRuntimeState")

	// Attempt to queue a message for an invalid runtime.
	var invalidRuntimeID common.Namespace
	_ = invalidRuntimeID.UnmarshalHex("000000000000000000000000000000000000000000000000000000000000DEAD")
	err = app.submitMsg(ctx, roothashState, &roothash.SubmitMsg{
		ID:   invalidRuntimeID,
		Data: []byte("hello world"),
	})
	require.Error(err, "SubmitMsg should fail for invalid runtime")
	require.ErrorIs(err, roothash.ErrInvalidRuntime)

	// Attempt to queue a message.
	err = app.submitMsg(ctx, roothashState, &roothash.SubmitMsg{
		ID:   runtime.ID,
		Data: []byte("hello world"),
	})
	require.Error(err, "SubmitMsg should fail when no messages allowed")
	require.ErrorIs(err, roothash.ErrIncomingMessageQueueFull)

	// Update runtime configuration to allow some incoming messages.
	rtState.Runtime.TxnScheduler.MaxInMessages = 1
	rtState.Runtime.Staking.MinInMessageFee = *quantity.NewFromUint64(100)
	err = roothashState.SetRuntimeState(ctx, &rtState)
	require.NoError(err, "SetRuntimeState")

	// Attempt to queue a message again.
	err = app.submitMsg(ctx, roothashState, &roothash.SubmitMsg{
		ID:   runtime.ID,
		Data: []byte("hello world"),
	})
	require.Error(err, "SubmitMsg should fail when fee is too low")
	require.ErrorIs(err, roothash.ErrIncomingMessageInsufficientFee)

	// Attempt to queue a message with fee specified (but insufficient funds for fee).
	err = app.submitMsg(ctx, roothashState, &roothash.SubmitMsg{
		ID:   runtime.ID,
		Fee:  *quantity.NewFromUint64(100),
		Data: []byte("hello world"),
	})
	require.Error(err, "SubmitMsg should fail when there is not enough balance to pay fees")
	require.ErrorIs(err, staking.ErrInsufficientBalance)

	// Allocate some funds to the caller.
	err = stakingState.SetAccount(ctx, callerAddress, &staking.Account{
		General: staking.GeneralAccount{
			Balance: *quantity.NewFromUint64(300),
		},
	})
	require.NoError(err, "SetAccount")

	// Attempt to queue a message with fee specified (but insufficient funds for sent tokens).
	err = app.submitMsg(ctx, roothashState, &roothash.SubmitMsg{
		ID:     runtime.ID,
		Fee:    *quantity.NewFromUint64(100),
		Tokens: *quantity.NewFromUint64(1000),
		Data:   []byte("hello world"),
	})
	require.Error(err, "SubmitMsg should fail when there is not enough balance to pay for sent tokens")
	require.ErrorIs(err, staking.ErrInsufficientBalance)

	// Attempt to queue a message.
	msg := roothash.SubmitMsg{
		ID:     runtime.ID,
		Fee:    *quantity.NewFromUint64(100),
		Tokens: *quantity.NewFromUint64(50),
		Data:   []byte("hello world 1"),
	}
	err = app.submitMsg(ctx, roothashState, &msg)
	require.NoError(err, "SubmitMsg should succeed")

	// Make sure the runtime received the funds.
	rtAcc, err := stakingState.Account(ctx, staking.NewRuntimeAddress(runtime.ID))
	require.NoError(err, "Account")
	require.EqualValues(quantity.NewFromUint64(150), &rtAcc.General.Balance, "tokens must have been transferred to runtime")

	// Attempt to queue a message (after queue is full).
	err = app.submitMsg(ctx, roothashState, &roothash.SubmitMsg{
		ID:     runtime.ID,
		Fee:    *quantity.NewFromUint64(100),
		Tokens: *quantity.NewFromUint64(50),
		Data:   []byte("hello world 2"),
	})
	require.Error(err, "SubmitMsg should fail when the queue is full")
	require.ErrorIs(err, roothash.ErrIncomingMessageQueueFull)

	// Check that metadata is correct.
	meta, err := roothashState.IncomingMessageQueueMeta(ctx, runtime.ID)
	require.NoError(err, "IncomingMessageQueueMeta")
	require.EqualValues(1, meta.NextSequenceNumber)
	require.EqualValues(1, meta.Size)

	// Check that message has been queued.
	msgs, err := roothashState.IncomingMessageQueue(ctx, runtime.ID, 0, 0)
	require.NoError(err, "IncomingMessageQueue")
	require.Len(msgs, 1, "one incoming message should be queued")
	require.EqualValues(0, msgs[0].ID)
	require.EqualValues(callerAddress, msgs[0].Caller)
	require.EqualValues(msg.Fee, msgs[0].Fee)
	require.EqualValues(msg.Tokens, msgs[0].Tokens)
	require.EqualValues(msg.Data, msgs[0].Data)

	// Pop message from queue.
	err = roothashState.RemoveIncomingMessageFromQueue(ctx, runtime.ID, 0)
	require.NoError(err, "RemoveIncomingMessageFromQueue")
	msgs, err = roothashState.IncomingMessageQueue(ctx, runtime.ID, 0, 0)
	require.NoError(err, "IncomingMessageQueue")
	require.Empty(msgs, "queue should be empty")
}
