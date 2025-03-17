package runtime

import (
	"context"
	"fmt"
	"slices"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// HistoryReindex is the scenario that triggers block history reindexing.
var HistoryReindex scenario.Scenario = newHistoryReindexImpl()

type historyReindexImpl struct {
	Scenario
	rtIdx int
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

	// Find the first compute runtime.
	rtIdx := slices.IndexFunc(f.Runtimes, func(rt oasis.RuntimeFixture) bool {
		return rt.Kind == registry.KindCompute
	})
	if rtIdx == -1 {
		return nil, fmt.Errorf("no compute runtime configured")
	}
	sc.rtIdx = rtIdx

	// Run selected runtime on a single compute node.
	f.ComputeWorkers = f.ComputeWorkers[:1]
	f.Runtimes[rtIdx].Executor.GroupSize = 1
	f.Runtimes[rtIdx].Executor.GroupBackupSize = 0
	f.Runtimes[rtIdx].Constraints[scheduler.KindComputeExecutor][scheduler.RoleWorker].MinPoolSize.Limit = 1
	f.Runtimes[rtIdx].Constraints[scheduler.KindComputeExecutor][scheduler.RoleBackupWorker].MinPoolSize.Limit = 0

	// Start client without any runtime.
	f.Clients[0].Runtimes = nil

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

	// Prepare few runtime blocks for reindex.
	compute := sc.Net.ComputeWorkers()[0]
	computeCtrl, err := oasis.NewController(compute.SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller: %w", err)
	}
	err = sc.waitForClientRuntimeBlock(ctx, computeCtrl.RuntimeClient, 10)
	if err != nil {
		return fmt.Errorf("failed to wait for runtime block: %w", err)
	}

	// Reindex existing runtime blocks and start indexing new ones.
	client := sc.Net.Clients()[0]
	client.UpdateRuntimes([]int{sc.rtIdx})
	if err = client.Restart(ctx); err != nil {
		return fmt.Errorf("failed to restart %s: %w", client.Name, err)
	}

	// Verify that indexing works.
	if err := sc.waitForClientRuntimeBlock(ctx, sc.Net.ClientController().RuntimeClient, 20); err != nil {
		return fmt.Errorf("failed to wait for runtime block: %w", err)
	}

	// Verify (re)indexed runtime blocks.
	for round := uint64(0); round <= 20; round++ {
		if err := sc.ensureEqualBlock(ctx, computeCtrl.RuntimeClient, sc.Net.ClientController().RuntimeClient, round); err != nil {
			return fmt.Errorf("failed to ensure %s and %s equal blocks (round: %d): %w", compute.Name, client.Name, round, err)
		}
	}

	// Run test client to ensure runtime works.
	sc.Logger.Info("starting the basic test client")
	if err = sc.RunTestClientAndCheckLogs(ctx, childEnv); err != nil {
		return fmt.Errorf("failed to run test client and check logs: %w", err)
	}

	return nil
}

func (sc *historyReindexImpl) waitForClientRuntimeBlock(ctx context.Context, client api.RuntimeClient, round uint64) error {
	rtID := sc.Net.Runtimes()[sc.rtIdx].ID()
	ch, sub, err := client.WatchBlocks(ctx, rtID)
	if err != nil {
		return fmt.Errorf("failed to watch runtime blocks: %w)", err)
	}
	defer sub.Close()
	if _, err := sc.WaitRuntimeBlock(ctx, ch, round); err != nil {
		return fmt.Errorf("failed to wait for runtime round %d: %w", round, err)
	}
	return nil
}

func (sc *historyReindexImpl) ensureEqualBlock(ctx context.Context, client1, client2 api.RuntimeClient, round uint64) error {
	blk1, err := sc.fetchRuntimeBlock(ctx, client1, round)
	if err != nil {
		return fmt.Errorf("failed to fetch client1's runtime block: %w", err)
	}
	blk2, err := sc.fetchRuntimeBlock(ctx, client2, round)
	if err != nil {
		return fmt.Errorf("failed to fetch client2's runtime block: %w", err)
	}

	hash1 := blk1.Header.EncodedHash()
	hash2 := blk2.Header.EncodedHash()
	if !hash1.Equal(&hash2) {
		return fmt.Errorf("block header hash not equal: want %s, got %s", hash1, hash2)
	}

	return nil
}

func (sc *historyReindexImpl) fetchRuntimeBlock(ctx context.Context, client api.RuntimeClient, round uint64) (*block.Block, error) {
	blk, err := client.GetBlock(ctx, &api.GetBlockRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     round,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get block: %w", err)
	}
	return blk, nil
}
