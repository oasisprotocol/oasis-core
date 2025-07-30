package runtime

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// CheckpointSync tests interoperability of the new checkpoint and diff sync
// p2p protocols with the legacy storage sync p2p protocol.
//
// The test checks that hosts that serve both protocols are compatible
// with clients that fallback to both.
//
// To simulate legacy host comment out fallback to the new protocols
// inside storage committee worker and disable registration of new checkpoint
// and diff sync protocols. This is not tested automatically as it would
// further pollute existing code and require additional config flags.
var CheckpointSync scenario.Scenario = newCheckpointSyncImpl()

type checkpointSync struct {
	Scenario
}

func newCheckpointSyncImpl() scenario.Scenario {
	return &checkpointSync{
		Scenario: *NewScenario(
			"checkpoint-sync",
			NewTestClient().WithScenario(SimpleScenario),
		),
	}
}

func (sc *checkpointSync) Clone() scenario.Scenario {
	return &checkpointSync{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *checkpointSync) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Make the first compute worker check for checkpoints more often.
	f.ComputeWorkers[0].CheckpointCheckInterval = time.Second
	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 10
	f.Runtimes[1].Storage.CheckpointChunkSize = 1024
	// Serve both legacy and new protocols.
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].LegacySyncServerDisabled = false
	}
	f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{
		NodeFixture: oasis.NodeFixture{
			NoAutoStart: true,
		},
		Entity:                1,
		Runtimes:              []int{1},
		CheckpointSyncEnabled: true,
		LogWatcherHandlerFactories: []log.WatcherHandlerFactory{
			oasis.LogAssertCheckpointSync(),
		},
	})

	return f, nil
}

func (sc *checkpointSync) Run(ctx context.Context, _ *env.Env) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	if err := sc.WaitForClientSync(ctx); err != nil {
		return fmt.Errorf("failed to wait for client sync: %w", err)
	}

	// Generate some more rounds to trigger checkpointing.
	for i := 0; i < 15; i++ {
		sc.Logger.Info("submitting transaction to runtime", "seq", i)
		if _, err := sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, uint64(i), "checkpoint", strconv.Itoa(i), 0, 0, plaintextTxKind); err != nil {
			return err
		}
	}

	// Make sure that the first compute node created checkpoints.
	ctrl, err := oasis.NewController(sc.Net.ComputeWorkers()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to connect with the first compute node: %w", err)
	}
	if _, err = ctrl.Storage.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1, Namespace: KeyValueRuntimeID}); err != nil {
		return fmt.Errorf("failed to get checkpoints: %w", err)
	}

	// Start late compute worker and check if it syncs with a checkpoint.
	sc.Logger.Info("running late compute worker")
	lateWorker := sc.Net.ComputeWorkers()[len(sc.Net.ComputeWorkers())-1]
	if err = lateWorker.Start(); err != nil {
		return fmt.Errorf("failed to start late compute worker: %w", err)
	}
	if err = lateWorker.WaitReady(ctx); err != nil {
		return fmt.Errorf("failed to wait for late compute worker to become ready: %w", err)
	}

	// Wait a bit to give the logger in the node time to sync to disk.
	<-time.After(1 * time.Second)

	return sc.Net.CheckLogWatchers()
}
