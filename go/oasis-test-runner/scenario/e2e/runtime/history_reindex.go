package runtime

import (
	"context"
	"fmt"

	"github.com/google/go-cmp/cmp"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	reindexComputePruneNumKept = 50
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
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *historyReindexImpl) Run(ctx context.Context, childEnv *env.Env) error {
	// Start the network.
	if err := sc.Net.Start(); err != nil {
		return err
	}

	// Wait for enough block to ensure pruning on the compute node.
	if err := sc.ensureComputePruning(ctx); err != nil {
		return fmt.Errorf("failed to ensure compute node pruning: %w", err)
	}

	// Restart compute worker with configured runtime.
	if err := sc.restartCompute(ctx, childEnv); err != nil {
		return fmt.Errorf("failed to restart compute node: %w", err)
	}

	// Run client to ensure runtime works.
	sc.Logger.Info("Starting the basic client")
	if err := sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return fmt.Errorf("failed to run test client and check logs: %w", err)
	}

	// Start a new client and ensure reindex works, by comparing all blocks
	// of default scenario client with the new client.
	return sc.startNewClientAndTestReindex(ctx)
}

func (sc *historyReindexImpl) startNewClientAndTestReindex(ctx context.Context) error {
	lastRound, err := sc.fetchLatestRound(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch default client latest round: %w", err)
	}

	client, err := sc.starNewClient()
	if err != nil {
		return fmt.Errorf("failed to start a new client: %w", err)
	}
	clientCtrl, err := oasis.NewController(client.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create client controller: %w", err)
	}

	if err := sc.waitRound(ctx, lastRound, clientCtrl.RuntimeClient); err != nil {
		return fmt.Errorf("failed to wait for client to catch round %d: %w", lastRound, err)
	}

	if err = sc.ensureEqualHistory(ctx, clientCtrl.RuntimeClient, 0, lastRound); err != nil {
		return fmt.Errorf("failed to ensure equal block history: %w", err)
	}

	return nil
}

func (sc *historyReindexImpl) ensureEqualHistory(
	ctx context.Context,
	client api.RuntimeClient,
	start, end uint64,
) error {
	sc.Logger.Info("ensure reindexed runtime block history is equal",
		"start_round", start,
		"end_round", end,
	)
	for r := start; r <= end; r++ {
		blk, err := sc.Net.ClientController().RuntimeClient.GetBlock(ctx, &api.GetBlockRequest{
			RuntimeID: KeyValueRuntimeID,
			Round:     r,
		})
		if err != nil {
			return fmt.Errorf("failed to get default client block (round: %d): %w", r, err)
		}

		if err = sc.ensureEqualBlock(ctx, client, r, blk); err != nil {
			return fmt.Errorf("failed to ensure equal block (round: %d): %w", r, err)
		}
	}
	return nil

}

func (sc *historyReindexImpl) ensureEqualBlock(
	ctx context.Context,
	client api.RuntimeClient,
	round uint64,
	want *block.Block,
) error {
	got, err := client.GetBlock(ctx, &api.GetBlockRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     round,
	})
	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	if diff := cmp.Diff(got, want); diff != "" {
		return fmt.Errorf("blocks not equal\n%s", diff)
	}

	return nil
}

func (sc *historyReindexImpl) ensureComputePruning(ctx context.Context) error {
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

	return nil
}

func (sc *historyReindexImpl) restartCompute(ctx context.Context, childEnv *env.Env) error {
	cli := cli.New(childEnv, sc.Net, sc.Logger)

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

	return nil
}

func (sc *historyReindexImpl) starNewClient() (*oasis.Client, error) {
	var rtIdx int
	for idx, rt := range sc.Net.Runtimes() {
		if rt.Kind() == registry.KindCompute {
			rtIdx = idx
			break
		}
	}

	rtProv, err := sc.Scenario.runtimeProvisioner()
	if err != nil {
		return nil, fmt.Errorf("failed to get runtime provisioner: %w", err)
	}
	cfg := &oasis.ClientCfg{
		Runtimes:           []int{rtIdx},
		RuntimeProvisioner: rtProv,
	}
	client, err := sc.Net.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new client: %w", err)
	}

	if err = client.Start(); err != nil {
		return nil, fmt.Errorf("failed to start %s: %w", client.Name, err)
	}
	sc.Logger.Info("started new client node",
		"name", client.Name,
	)

	return client, nil
}

func (sc *historyReindexImpl) waitRound(ctx context.Context, round uint64, client api.RuntimeClient) error {
	sc.Logger.Info("waiting for runtime round", "round", round)
	ch, sub, err := client.WatchBlocks(ctx, KeyValueRuntimeID)
	if err != nil {
		return fmt.Errorf("failed to watch runtime blocks: %w", err)
	}
	defer sub.Close()
	for {
		select {
		case annBlk, ok := <-ch:
			if !ok {
				return fmt.Errorf("watch blocks channel closed unexpectedly")
			}

			if annBlk.Block.Header.Round >= round {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (sc *historyReindexImpl) fetchLatestRound(ctx context.Context) (uint64, error) {
	latestBlock, err := sc.Net.ClientController().RuntimeClient.GetBlock(ctx, &api.GetBlockRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     api.RoundLatest,
	})
	if err != nil {
		return 0, fmt.Errorf("failed to get latest block: %w", err)
	}
	round := latestBlock.Header.Round
	sc.Logger.Info("latest block", "round", round)
	return round, nil
}
