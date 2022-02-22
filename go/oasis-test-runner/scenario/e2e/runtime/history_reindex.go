package runtime

import (
	"context"
	"fmt"
	"path/filepath"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	reindexComputePruneNumKept = 50
)

// HistoryReindex is the scenario that triggers roothash history reindexing.
var HistoryReindex scenario.Scenario = newHistoryReindexImpl()

type historyReindexImpl struct {
	runtimeImpl
}

func newHistoryReindexImpl() scenario.Scenario {
	return &historyReindexImpl{
		runtimeImpl: *newRuntimeImpl("history-reindex", BasicKVEncTestClient),
	}
}

func (sc *historyReindexImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	f.ComputeWorkers = []oasis.ComputeWorkerFixture{
		{
			Entity:   1,
			Runtimes: []int{},
			Consensus: oasis.ConsensusFixture{
				PruneNumKept: reindexComputePruneNumKept,
			},
			LogWatcherHandlerFactories: []log.WatcherHandlerFactory{
				// Ensure ABCI pruning happens on the node.
				oasis.LogEventABCIPruneDelete(),
				// Ensure re-indexing happens on the node.
				oasis.LogAssertRoothashRoothashReindexing(),
			},
		},
	}

	// Assumes a single compute runtime.
	var rtIdx int
	for idx, rt := range f.Runtimes {
		if rt.Kind == registry.KindCompute {
			rtIdx = idx
			break
		}
	}
	// Compute runtime will be registered later.
	f.Runtimes[rtIdx].ExcludeFromGenesis = true
	// Use a single compute node.
	f.Runtimes[rtIdx].Executor.GroupSize = 1
	f.Runtimes[rtIdx].Executor.GroupBackupSize = 0
	f.Runtimes[rtIdx].Constraints[scheduler.KindComputeExecutor][scheduler.RoleWorker].MinPoolSize.Limit = 1
	f.Runtimes[rtIdx].Constraints[scheduler.KindComputeExecutor][scheduler.RoleBackupWorker].MinPoolSize.Limit = 0

	return f, nil
}

func (sc *historyReindexImpl) Clone() scenario.Scenario {
	return &historyReindexImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *historyReindexImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Start the network.
	if err := sc.Net.Start(); err != nil {
		return err
	}

	// Wait for enough block to ensure pruning on the compute node.
	waitForHeight := int64(reindexComputePruneNumKept + 20)
	sc.Logger.Info("waiting enough blocks to ensure pruning",
		"compute_prune_num_kept", reindexComputePruneNumKept,
		"wait_for_height", waitForHeight,
	)

	blockCh, blockSub, bErr := sc.Net.Controller().Consensus.WatchBlocks(ctx)
	if bErr != nil {
		return fmt.Errorf("failed waiting for block height: %w", bErr)
	}
	defer blockSub.Close()

	for newBlk := range blockCh {
		if newBlk.Height > waitForHeight {
			break
		}
		sc.Logger.Debug("waiting enough blocks to ensure pruning",
			"current_height", newBlk.Height,
			"wait_for_height", waitForHeight,
		)
	}

	// Restart compute worker with configured runtime.
	compute := sc.Net.ComputeWorkers()[0]
	sc.Logger.Info("stopping the compute worker")
	if err := compute.Stop(); err != nil {
		return err
	}
	var rtIdx int
	for idx, rt := range sc.Net.Runtimes() {
		if rt.Kind() == registry.KindCompute {
			rtIdx = idx
			break
		}
	}
	// Update worker runtime configuration.
	compute.UpdateRuntimes([]int{rtIdx})
	sc.Logger.Info("starting the compute worker")
	if err := compute.Start(); err != nil {
		return err
	}

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register runtime.
	compRt := sc.Net.Runtimes()[rtIdx]
	txPath := filepath.Join(childEnv.Dir(), "register_compute_runtime.json")
	rtDsc := compRt.ToRuntimeDescriptor()
	rtDsc.Deployments[0].ValidFrom = epoch + 1
	if err = cli.Registry.GenerateRegisterRuntimeTx(childEnv.Dir(), compRt.ToRuntimeDescriptor(), 0, txPath); err != nil {
		return fmt.Errorf("failed to generate register compute runtime tx: %w", err)
	}
	if err = cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to register compute runtime: %w", err)
	}

	// Wait for the compute worker to be ready.
	sc.Logger.Info("waiting for the compute worker to become ready")
	computeCtrl, err := oasis.NewController(compute.SocketPath())
	if err != nil {
		return err
	}
	if err = computeCtrl.WaitReady(context.Background()); err != nil {
		return err
	}

	// Run client to ensure runtime works.
	sc.Logger.Info("Starting the basic client")
	if err = sc.startTestClientOnly(ctx, childEnv); err != nil {
		return err
	}

	return sc.waitTestClient()
}
