package roothash

import (
	"crypto/rand"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashApi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
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
