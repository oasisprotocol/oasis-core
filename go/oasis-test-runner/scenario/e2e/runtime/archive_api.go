package runtime

import (
	"context"
	"fmt"
	"reflect"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
)

// ArchiveAPI is the scenario where archive node control, consensus and runtime APIs are tested.
var ArchiveAPI scenario.Scenario = &archiveAPI{
	runtimeImpl: *newRuntimeImpl(
		"archive-api",
		NewLongTermTestClient().WithMode(ModePart1),
	),
}

type archiveAPI struct {
	runtimeImpl
}

func (sc *archiveAPI) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}
	// Add a validator node that will be turned into an archive node.
	f.Validators = append(f.Validators, oasis.ValidatorFixture{Entity: 1, AllowEarlyTermination: true})

	// Add a compute node that will be turned into an archive node.
	f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{Entity: 1, Runtimes: []int{1}, AllowEarlyTermination: true})
	f.Runtimes[1].Executor.GroupSize++

	f.Network.SetMockEpoch()
	f.Network.HaltEpoch = uint64(haltEpoch)
	for _, val := range f.Validators {
		val.AllowEarlyTermination = true
	}
	for _, cw := range f.ComputeWorkers {
		cw.AllowEarlyTermination = true
	}

	return f, nil
}

func (sc *archiveAPI) Clone() scenario.Scenario {
	return &archiveAPI{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *archiveAPI) testArchiveAPI(ctx context.Context, archiveCtrl *oasis.Controller, runtime bool, halted bool) error { // nolint: gocyclo
	sc.Logger.Info("testing IsSynced")
	isSynced, err := archiveCtrl.IsSynced(ctx)
	if err != nil {
		return err
	}
	if !isSynced {
		return fmt.Errorf("archive node reports as not synced")
	}

	sc.Logger.Info("testing IsReady")
	isReady, err := archiveCtrl.IsReady(ctx)
	if err != nil {
		return err
	}
	switch {
	case runtime && isReady:
		return fmt.Errorf("runtime archive node reports ready to accept runtime work")
	case !runtime && !isReady:
		return fmt.Errorf("consensus archive node reports as not ready")
	default:
	}

	sc.Logger.Info("testing GetStatus")
	status, err := archiveCtrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("failed to get status for node: %w", err)
	}
	if status.Consensus.Mode != consensusAPI.ModeArchive {
		return fmt.Errorf("archive node consensus mode not archive, got: '%s'", status.Consensus.Mode)
	}
	if status.Consensus.LatestHeight == int64(0) {
		return fmt.Errorf("archive node latest height should not be 0")
	}
	if len(status.Consensus.NodePeers) != 0 {
		return fmt.Errorf("archive should not have any peers")
	}
	if p := status.PendingUpgrades; len(p) != 0 {
		return fmt.Errorf("unexpected pending upgrades: %v", p)
	}

	sc.Logger.Info("testing SetEpoch")
	if err = archiveCtrl.SetEpoch(ctx, beacon.EpochTime(0)); err == nil {
		return fmt.Errorf("archive node SetEpoch should fail")
	}

	sc.Logger.Info("testing GetGenesisDocument")
	doc, err := archiveCtrl.Consensus.GetGenesisDocument(ctx)
	if err != nil {
		return fmt.Errorf("archive node GetGenesisDocument should work")
	}
	if doc == nil {
		return fmt.Errorf("archive node GetGenesisDocument should not be nil")
	}

	sc.Logger.Info("testing SubmitTx")
	err = archiveCtrl.Consensus.SubmitTx(ctx, &transaction.SignedTransaction{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("archive node SubmitTx should fail with unsupported")
	}

	sc.Logger.Info("testing SubmitTxNoWait")
	err = archiveCtrl.Consensus.SubmitTxNoWait(ctx, &transaction.SignedTransaction{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("archive node SubmitTxNoWait should fail with unsupported")
	}

	sc.Logger.Info("testing SubmitEvidence")
	err = archiveCtrl.Consensus.SubmitEvidence(ctx, &consensusAPI.Evidence{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("archive node SubmitEvidence should fail with unsupported")
	}

	sc.Logger.Info("testing StateToGenesis")
	_, err = archiveCtrl.Consensus.StateToGenesis(ctx, 0)
	if err != nil {
		return fmt.Errorf("archive node StateToGenesis should work: %w", err)
	}

	sc.Logger.Info("testing EstimateGas")
	_, err = archiveCtrl.Consensus.EstimateGas(ctx, &consensusAPI.EstimateGasRequest{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("archive node EstimateGas should fail with unsupported")
	}

	sc.Logger.Info("testing GetBlock")
	archiveBlock, err := archiveCtrl.Consensus.GetBlock(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return fmt.Errorf("archive node GetBlock should work: %w", err)
	}

	sc.Logger.Info("testing GetTransactions")
	_, err = archiveCtrl.Consensus.GetTransactions(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return fmt.Errorf("archive node GetTransactions should work: %w", err)
	}

	sc.Logger.Info("testing GetTransactionsWithResults")
	_, err = archiveCtrl.Consensus.GetTransactionsWithResults(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return fmt.Errorf("archive node GetTransactions should work: %w", err)
	}

	sc.Logger.Info("testing GetUnconfirmedTransactions")
	_, err = archiveCtrl.Consensus.GetUnconfirmedTransactions(ctx)
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("archive node GetUnconfirmedTransactions should work: %w", err)
	}

	sc.Logger.Info("testing GetSignerNonce")
	_, err = archiveCtrl.Consensus.GetSignerNonce(ctx, &consensusAPI.GetSignerNonceRequest{})
	if err != consensusAPI.ErrUnsupported {
		return fmt.Errorf("archive node GetSignerNonce should fail with unsupported")
	}

	sc.Logger.Info("testing GetLightBlock")
	_, err = archiveCtrl.Consensus.GetLightBlock(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return fmt.Errorf("archive node GetLightBlock should work: %w", err)
	}

	sc.Logger.Info("testing GetParameters")
	_, err = archiveCtrl.Consensus.GetParameters(ctx, consensusAPI.HeightLatest)
	if err != nil {
		return fmt.Errorf("archive node GetParameters should work: %w", err)
	}

	if !halted {
		var blockCh <-chan *consensusAPI.Block
		var blockSub pubsub.ClosableSubscription
		// Wait some blocks.
		blockCh, blockSub, err = sc.Net.Controller().Consensus.WatchBlocks(ctx)
		if err != nil {
			return err
		}
		defer blockSub.Close()

		sc.Logger.Info("waiting for some blocks")
		var wait uint
		for {
			if wait > 5 {
				break
			}
			select {
			case <-blockCh:
				wait++
			case <-time.After(30 * time.Second):
				return fmt.Errorf("timed out waiting for blocks")
			}
		}

		// Ensure archive node is not syncing.
		var validatorCtrl *oasis.Controller
		validatorCtrl, err = oasis.NewController(sc.Net.Validators()[0].SocketPath())
		if err != nil {
			return err
		}
		var valBlock *consensusAPI.Block
		valBlock, err = validatorCtrl.Consensus.GetBlock(ctx, consensusAPI.HeightLatest)
		if err != nil {
			return fmt.Errorf("client GetBlock: %w", err)
		}
		var archiveBlock2 *consensusAPI.Block
		archiveBlock2, err = archiveCtrl.Consensus.GetBlock(ctx, consensusAPI.HeightLatest)
		if err != nil {
			return fmt.Errorf("archive node GetBlock should work: %w", err)
		}
		if archiveBlock.Height != archiveBlock2.Height {
			return fmt.Errorf("archive node latest block changed from: %d to: %d", archiveBlock.Height, archiveBlock2.Height)
		}
		if valBlock.Height <= archiveBlock.Height {
			return fmt.Errorf("client latest block height (%d) should be higher than latest archive block height (%d)", valBlock.Height, archiveBlock.Height)
		}
	}

	if !runtime {
		return nil
	}

	// Test runtime queries.
	rtClient := archiveCtrl.RuntimeClient
	sc.Logger.Info("testing runtime GetBlock")
	blk, err := rtClient.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: api.RoundLatest})
	if err != nil {
		return fmt.Errorf("runtime GetBlock: %w", err)
	}
	if blk.Header.Round == 0 {
		return fmt.Errorf("unexpected latest runtime round: %d", blk.Header.Round)
	}

	sc.Logger.Info("testing runtime GetEvents")
	_, err = rtClient.GetEvents(ctx, &api.GetEventsRequest{RuntimeID: runtimeID, Round: api.RoundLatest})
	if err != nil {
		return fmt.Errorf("runtime GetEvents: %w", err)
	}

	sc.Logger.Info("testing runtime GetLastRetainBlock")
	_, err = rtClient.GetLastRetainedBlock(ctx, runtimeID)
	if err != nil {
		return fmt.Errorf("runtime GetLastRetainedBlock: %w", err)
	}

	sc.Logger.Info("testing runtime GetTransactions")
	_, err = rtClient.GetTransactions(ctx, &api.GetTransactionsRequest{RuntimeID: runtimeID, Round: api.RoundLatest})
	if err != nil {
		return fmt.Errorf("runtime GetTransactions: %w", err)
	}

	sc.Logger.Info("testing runtime GetTransactionsWithResults")
	_, err = rtClient.GetTransactionsWithResults(ctx, &api.GetTransactionsRequest{RuntimeID: runtimeID, Round: api.RoundLatest})
	if err != nil {
		return fmt.Errorf("runtime GetTransactionsWithResults: %w", err)
	}

	sc.Logger.Info("testing runtime WatchBlocks")
	_, sub, err := rtClient.WatchBlocks(ctx, runtimeID)
	if err != nil {
		return fmt.Errorf("runtime WatchBlocks: %w", err)
	}
	defer sub.Close()
	return nil
}

func (sc *archiveAPI) Run(childEnv *env.Env) error {
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}
	var nextEpoch beacon.EpochTime
	if nextEpoch, err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}
	nextEpoch++ // Next, after initial transitions.

	// Wait for the client to exit.
	sc.Logger.Info("waiting for test client to exit")
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	// Convert a validator into an archive node.
	sc.Logger.Info("converting validator 3 into an archive node")
	if err = sc.Net.Validators()[3].Stop(); err != nil {
		return fmt.Errorf("stopping validator: %w", err)
	}
	sc.Net.Validators()[3].SetArchiveMode(true)
	if err = sc.Net.Validators()[3].Start(); err != nil {
		return fmt.Errorf("starting validator as archive: %w", err)
	}
	valArchive, err := oasis.NewController(sc.Net.Validators()[3].SocketPath())
	if err != nil {
		return err
	}
	sc.Logger.Info("testing validator archive API")
	if err = sc.testArchiveAPI(ctx, valArchive, false, false); err != nil {
		return fmt.Errorf("validator archive api: %w", err)
	}

	// Convert a compute worker into an archive node.
	sc.Logger.Info("converting compute worker 3 into an archive node")
	if err = sc.Net.ComputeWorkers()[3].Stop(); err != nil {
		return fmt.Errorf("stopping compute worker: %w", err)
	}
	sc.Net.ComputeWorkers()[3].SetArchiveMode(true)
	if err = sc.Net.ComputeWorkers()[3].Start(); err != nil {
		return fmt.Errorf("starting compute worker as archive: %w", err)
	}
	computeArchive, err := oasis.NewController(sc.Net.ComputeWorkers()[3].SocketPath())
	if err != nil {
		return err
	}
	sc.Logger.Info("testing compute worker archive API")
	if err = sc.testArchiveAPI(ctx, computeArchive, true, false); err != nil {
		return fmt.Errorf("compute archive api: %w", err)
	}

	// Transition to halt epoch.
	sc.Logger.Info("transitioning to halt epoch",
		"halt_epoch", haltEpoch,
	)
	for i := nextEpoch; i <= beacon.EpochTime(haltEpoch); i++ {
		sc.Logger.Info("setting epoch",
			"epoch", i,
		)
		if err = sc.Net.Controller().SetEpoch(ctx, i); err != nil {
			return fmt.Errorf("failed to set epoch %d: %w", i, err)
		}
	}

	// Wait for validators to exit.
	sc.Logger.Info("wait for nodes to exit")
	var exitChs []reflect.SelectCase
	for _, val := range sc.Net.Validators() {
		exitChs = append(exitChs, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(val.Exit()),
		})
	}
	// Exit status doesn't matter, we only need one of the validators to stop existing.
	_, _, _ = reflect.Select(exitChs)

	sc.Logger.Info("network halted, testing archive nodes on a halted network")

	// Convert validator 0 into an archive node.
	sc.Logger.Info("converting validator 0 into an archive node")
	if err = sc.Net.Validators()[0].Stop(); err != nil {
		return fmt.Errorf("stopping validator: %w", err)
	}
	sc.Net.Validators()[0].SetArchiveMode(true)
	if err = sc.Net.Validators()[0].Start(); err != nil {
		return fmt.Errorf("starting validator as archive: %w", err)
	}
	valArchive, err = oasis.NewController(sc.Net.Validators()[0].SocketPath())
	if err != nil {
		return err
	}
	sc.Logger.Info("testing validator archive API")
	if err = sc.testArchiveAPI(ctx, valArchive, false, true); err != nil {
		return fmt.Errorf("validator archive api: %w", err)
	}

	// Convert compute 0 into an archive node.
	sc.Logger.Info("converting comptue worker 0 into an archive node")
	if err = sc.Net.ComputeWorkers()[0].Stop(); err != nil {
		return fmt.Errorf("stopping compute worker: %w", err)
	}
	sc.Net.ComputeWorkers()[0].SetArchiveMode(true)
	if err = sc.Net.ComputeWorkers()[0].Start(); err != nil {
		return fmt.Errorf("starting compute worker as archive: %w", err)
	}
	computeArchive, err = oasis.NewController(sc.Net.ComputeWorkers()[0].SocketPath())
	if err != nil {
		return err
	}
	sc.Logger.Info("testing compute worker archive API")
	if err = sc.testArchiveAPI(ctx, computeArchive, true, true); err != nil {
		return fmt.Errorf("compute worker archive api: %w", err)
	}

	return nil
}
