package runtime

import (
	"context"
	"fmt"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// HistoryReindex is the scenario that triggers roothash history reindexing.
var HistoryReindex scenario.Scenario = newHistoryReindexImpl()

type historyReindexImpl struct {
	Scenario
}

func newHistoryReindexImpl() scenario.Scenario {
	return &historyReindexImpl{
		Scenario: *NewScenario(
			"history-reindex",
			NewTestClient().WithScenario(InsertRemoveEncWithSecretsScenario),
		),
	}
}

func (sc *historyReindexImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	f.ComputeWorkers = []oasis.ComputeWorkerFixture{
		{
			Entity:   1,
			Runtimes: []int{},
			LogWatcherHandlerFactories: []log.WatcherHandlerFactory{
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
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *historyReindexImpl) Run(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Start the network.
	if err := sc.Net.Start(); err != nil {
		return err
	}

	// Wait for one block so that initial epoch can be fetched below.
	if _, err := sc.WaitBlocks(ctx, 1); err != nil {
		return fmt.Errorf("failed to wait for one block: %w", err)
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
	rtDsc := compRt.ToRuntimeDescriptor()
	rtDsc.Deployments[0].ValidFrom = epoch + 1
	if err = sc.RegisterRuntime(childEnv, cli, rtDsc, 0); err != nil {
		return err
	}

	// Wait for the compute worker to be ready.
	sc.Logger.Info("waiting for the compute worker to become ready")
	computeCtrl, err := oasis.NewController(compute.SocketPath())
	if err != nil {
		return err
	}
	if err = computeCtrl.WaitReady(ctx); err != nil {
		return err
	}

	// Run client to ensure runtime works.
	sc.Logger.Info("Starting the basic client")
	return sc.RunTestClientAndCheckLogs(ctx, childEnv)
}
