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
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

type testMsgDispatcher struct{}

// Implements MessageDispatcher.
func (nd *testMsgDispatcher) Subscribe(interface{}, abciAPI.MessageSubscriber) {
}

// Implements MessageDispatcher.
func (nd *testMsgDispatcher) Publish(ctx *abciAPI.Context, kind, msg interface{}) error {
	// Either we need to be in simulation mode or the gas accountant must be a no-op one.
	if !ctx.IsSimulation() && ctx.Gas() != abciAPI.NewNopGasAccountant() {
		panic("gas estimation should always use simulation mode")
	}

	gasCosts := transaction.Costs{
		"transfer": 1000,
		"withdraw": 2000,
	}

	switch kind {
	case roothashApi.RuntimeMessageStaking:
		m := msg.(*message.StakingMessage)
		switch {
		case m.Transfer != nil:
			if err := ctx.Gas().UseGas(1, "transfer", gasCosts); err != nil {
				return err
			}
			return nil
		case m.Withdraw != nil:
			if err := ctx.Gas().UseGas(1, "withdraw", gasCosts); err != nil {
				return err
			}
			return nil
		default:
			return staking.ErrInvalidArgument
		}
	default:
		return staking.ErrInvalidArgument
	}
}

func TestMessagesGasEstimation(t *testing.T) {
	require := require.New(t)
	var err error

	genesisTestHelpers.SetTestChainContext()

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
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
	registryState := registryState.NewMutableState(ctx.State())
	_ = registryState
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
	storageCommittee := scheduler.Committee{
		RuntimeID: runtime.ID,
		Kind:      scheduler.KindStorage,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}
	err = schedulerState.PutCommittee(ctx, &storageCommittee)
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
	}
	msgsHash := message.MessagesHash(msgs)

	body := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        newBlk.Header.Round,
			PreviousHash: newBlk.Header.PreviousHash,
			IORoot:       &newBlk.Header.IORoot,
			StateRoot:    &newBlk.Header.StateRoot,
			MessagesHash: &msgsHash,
		},
		Messages: msgs,
	}

	// Generate storage receipts.
	receiptBody := storage.ReceiptBody{
		Version:   1,
		Namespace: newBlk.Header.Namespace,
		Round:     newBlk.Header.Round,
		Roots:     body.RootsForStorageReceipt(),
	}
	signedReceipt, err := signature.SignSigned(sk, storage.ReceiptSignatureContext, &receiptBody)
	require.NoError(err, "SignSigned")
	body.StorageSignatures = []signature.Signature{signedReceipt.Signature}

	// Generate txn scheduler signature.
	dispatch := &commitment.ProposedBatch{
		IORoot:            body.InputRoot,
		StorageSignatures: body.InputStorageSigs,
		Header:            blk.Header,
	}
	signedDispatch, err := commitment.SignProposedBatch(sk, dispatch)
	require.NoError(err, "SignProposedBatch")
	body.TxnSchedSig = signedDispatch.Signature

	commit, err := commitment.SignExecutorCommitment(sk, &body)
	require.NoError(err, "SignExecutorCommitment")

	// Generate executor commit transaction body.
	cc := &roothash.ExecutorCommit{
		ID:      runtime.ID,
		Commits: []commitment.ExecutorCommitment{*commit},
	}

	err = app.executorCommit(ctx, roothashState, cc)
	require.NoError(err, "ExecutorCommit")
	require.EqualValues(5000, ctx.Gas().GasUsed(), "gas amount should be correct")
}

func TestEvidence(t *testing.T) {
	require := require.New(t)
	var err error

	genesisTestHelpers.SetTestChainContext()

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
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
	storageCommittee := scheduler.Committee{
		RuntimeID: runtime.ID,
		Kind:      scheduler.KindStorage,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}
	err = schedulerState.PutCommittee(ctx, &storageCommittee)
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
	batch1 := &commitment.ProposedBatch{
		IORoot:            blk2.Header.IORoot,
		StorageSignatures: []signature.Signature{},
		Header:            blk2.Header,
	}
	signedBatch1, err := commitment.SignProposedBatch(sk, batch1)
	require.NoError(err, "SignProposedBatch")
	nonExistingSignerBatch1, err := commitment.SignProposedBatch(nonExistingSigner, batch1)
	require.NoError(err, "SignProposedBatch")

	batch2 := &commitment.ProposedBatch{
		IORoot:            hash.NewFromBytes([]byte("invalid root")),
		StorageSignatures: []signature.Signature{},
		Header:            blk2.Header,
	}
	signedBatch2, err := commitment.SignProposedBatch(sk, batch2)
	require.NoError(err, "SignProposedBatch")
	nonExistingSignerBatch2, err := commitment.SignProposedBatch(nonExistingSigner, batch2)
	require.NoError(err, "SignProposedBatch")

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
	body.Header.PreviousHash = hash.NewFromBytes([]byte("invalid ioroot"))
	signedCommitment2, err := commitment.SignExecutorCommitment(sk, &body)
	require.NoError(err, "SignExecutorCommitment")

	// Expired evidence.
	blk2.Header.Round = 25
	expired1 := &commitment.ProposedBatch{
		IORoot:            blk2.Header.IORoot,
		StorageSignatures: []signature.Signature{},
		Header:            blk2.Header,
	}
	expiredB1, err := commitment.SignProposedBatch(sk, expired1)
	require.NoError(err, "SignProposedBatch")
	expired2 := &commitment.ProposedBatch{
		IORoot:            hash.NewFromBytes([]byte("invalid root")),
		StorageSignatures: []signature.Signature{},
		Header:            blk2.Header,
	}
	expiredB2, err := commitment.SignProposedBatch(sk, expired2)
	require.NoError(err, "SignProposedBatch")

	expiredBody := commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        blk2.Header.Round,
			PreviousHash: blk2.Header.PreviousHash,
			IORoot:       &blk2.Header.IORoot,
			StateRoot:    &blk2.Header.StateRoot,
			MessagesHash: &hash.Hash{},
		},
	}
	expiredCommitment1, err := commitment.SignExecutorCommitment(sk, &expiredBody)
	require.NoError(err, "SignExecutorCommitment")
	expiredBody.Header.PreviousHash = hash.NewFromBytes([]byte("invalid ioroot"))
	expiredCommitment2, err := commitment.SignExecutorCommitment(sk, &expiredBody)
	require.NoError(err, "SignExecutorCommitment")
	var md testMsgDispatcher
	app := rootHashApplication{appState, &md}

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
				ID: common.NewTestNamespaceFromSeed([]byte("tendermint/apps/roothash/transaction_test: non existing runtime"), 0),
				EquivocationBatch: &roothash.EquivocationBatchEvidence{
					BatchA: *signedBatch1,
					BatchB: *signedBatch2,
				},
			},
			roothash.ErrInvalidRuntime,
			"evidence for nonexisting runtime",
		},
		{
			&roothash.Evidence{
				ID: runtimeNoSlashing.ID,
				EquivocationBatch: &roothash.EquivocationBatchEvidence{
					BatchA: *signedBatch1,
					BatchB: *signedBatch2,
				},
			},
			roothash.ErrRuntimeDoesNotSlash,
			"evidence for runtime without slashing",
		},
		{
			&roothash.Evidence{
				ID: runtimeZeroSlashing.ID,
				EquivocationBatch: &roothash.EquivocationBatchEvidence{
					BatchA: *signedBatch1,
					BatchB: *signedBatch2,
				},
			},
			roothash.ErrRuntimeDoesNotSlash,
			"evidence for runtime with zero slashing",
		},
		{
			&roothash.Evidence{
				EquivocationExecutor: &roothash.EquivocationExecutorEvidence{
					CommitA: *expiredCommitment1,
					CommitB: *expiredCommitment2,
				},
			},
			roothash.ErrInvalidEvidence,
			"expired executor evidence",
		},
		{
			&roothash.Evidence{
				EquivocationBatch: &roothash.EquivocationBatchEvidence{
					BatchA: *expiredB1,
					BatchB: *expiredB2,
				},
			},
			roothash.ErrInvalidEvidence,
			"expired batch evidence",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationExecutor: &roothash.EquivocationExecutorEvidence{
					CommitA: *signedCommitment1,
					CommitB: *signedCommitment2,
				},
			},
			nil,
			"valid executor evidence",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationBatch: &roothash.EquivocationBatchEvidence{
					BatchA: *signedBatch1,
					BatchB: *signedBatch2,
				},
			},
			nil,
			"valid batch evidence",
		},
		{
			&roothash.Evidence{
				ID: runtime.ID,
				EquivocationBatch: &roothash.EquivocationBatchEvidence{
					BatchA: *signedBatch1,
					BatchB: *signedBatch2,
				},
			},
			roothash.ErrDuplicateEvidence,
			"duplicate evidence",
		},
		{
			&roothash.Evidence{
				EquivocationBatch: &roothash.EquivocationBatchEvidence{
					BatchA: *nonExistingSignerBatch1,
					BatchB: *nonExistingSignerBatch2,
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
