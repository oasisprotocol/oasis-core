package runtime

import (
	"context"
	"fmt"
	"strings"
	"time"

	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

// StorageSync is the storage sync scenario.
var StorageSync scenario.Scenario = newStorageSyncImpl()

type storageSyncImpl struct {
	Scenario
}

func newStorageSyncImpl() scenario.Scenario {
	return &storageSyncImpl{
		Scenario: *NewScenario(
			"storage-sync",
			NewTestClient().WithScenario(SimpleKeyValueScenario),
		),
	}
}

func (sc *storageSyncImpl) Clone() scenario.Scenario {
	return &storageSyncImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *storageSyncImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Enable consensus layer checkpoints.
	f.Network.Consensus.Parameters.StateCheckpointInterval = 10
	f.Network.Consensus.Parameters.StateCheckpointNumKept = 2
	f.Network.Consensus.Parameters.StateCheckpointChunkSize = 1024 * 1024

	// Make the first compute worker check for checkpoints more often.
	f.ComputeWorkers[0].CheckpointCheckInterval = 1 * time.Second
	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 10
	f.Runtimes[1].Storage.CheckpointChunkSize = 1 * 1024

	// One more compute worker for later, so it can do an initial sync with the snapshots.
	f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{
		NodeFixture: oasis.NodeFixture{
			NoAutoStart: true,
		},
		Entity:                     1,
		Runtimes:                   []int{1},
		CheckpointSyncEnabled:      true,
		LogWatcherHandlerFactories: []log.WatcherHandlerFactory{oasis.LogAssertCheckpointSync()},
	})
	// And one more compute worker that will sync the consensus layer via state sync.
	f.ComputeWorkers = append(f.ComputeWorkers, oasis.ComputeWorkerFixture{
		NodeFixture: oasis.NodeFixture{
			NoAutoStart: true,
		},
		Entity:                1,
		Runtimes:              []int{1},
		CheckpointSyncEnabled: true,
		LogWatcherHandlerFactories: []log.WatcherHandlerFactory{
			oasis.LogAssertCheckpointSync(),
			oasis.LogEventABCIStateSyncComplete(),
		},
	})

	return f, nil
}

func (sc *storageSyncImpl) Run(ctx context.Context, childEnv *env.Env) error { //nolint: gocyclo
	var err error
	if err = sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	// Wait for the client to exit.
	if err = sc.WaitTestClient(); err != nil {
		return err
	}

	drbg, _ := drbgFromSeed([]byte("storage-sync/seq"), []byte("plant_your_seeds"))

	// Generate some more rounds to trigger checkpointing. Up to this point there have been ~9
	// rounds, we create 15 more rounds to bring this up to ~24. Checkpoints are every 10 rounds so
	// this leaves some space for any unintended epoch transitions.
	for i := 0; i < 15; i++ {
		sc.Logger.Info("submitting transaction to runtime",
			"seq", i,
		)
		if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, drbg.Uint64(), "checkpoint", fmt.Sprintf("my cp %d", i), false, 0); err != nil {
			return err
		}
	}

	// Make sure that the first compute node created checkpoints.
	ctrl, err := oasis.NewController(sc.Net.ComputeWorkers()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to connect with the first compute node: %w", err)
	}

	cps, err := ctrl.Storage.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1, Namespace: KeyValueRuntimeID})
	if err != nil {
		return fmt.Errorf("failed to get checkpoints: %w", err)
	}

	blk, err := ctrl.RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     runtimeClient.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	// Determine which checkpoints should be there.
	rt := sc.Net.Runtimes()[1].ToRuntimeDescriptor()
	lastCheckpoint := (blk.Header.Round / rt.Storage.CheckpointInterval) * rt.Storage.CheckpointInterval
	sc.Logger.Info("determined last expected checkpoint round",
		"round", lastCheckpoint,
	)

	// There should be at least two checkpoints. There may be more
	// depending on the state of garbage collection process (which
	// may be one checkpoint behind.)
	if numCps := len(cps); numCps < 2 {
		return fmt.Errorf("incorrect number of checkpoints (expected: >=2 got: %d)", numCps)
	}

	var validCps int
	for checkpoint := rt.Storage.CheckpointInterval; checkpoint <= lastCheckpoint; checkpoint += rt.Storage.CheckpointInterval {
		blk, err = ctrl.RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
			RuntimeID: KeyValueRuntimeID,
			Round:     checkpoint,
		})
		if err != nil {
			return fmt.Errorf("failed to get block %d: %w", checkpoint, err)
		}
		for _, cp := range cps {
			if cp.Root.Version != blk.Header.Round {
				continue
			}
			var found bool
			for _, root := range blk.Header.StorageRoots() {
				if root.Equal(&cp.Root) { //nolint:gosec
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("checkpoint for unexpected root %s", cp.Root)
			}
			sc.Logger.Info("found valid checkpoint",
				"round", checkpoint,
				"root_hash", cp.Root.Hash,
			)
			validCps++
		}
	}
	if validCps < 2 {
		return fmt.Errorf("incorrect number of valid checkpoints (expected: >=2 got: %d)", validCps)
	}

	largeVal := strings.Repeat("has he his auto ", 7) // 16 bytes base string
	for i := 0; i < 32; i++ {
		sc.Logger.Info("submitting large transaction to runtime",
			"seq", i,
		)
		if _, err = sc.submitKeyValueRuntimeInsertTx(ctx, KeyValueRuntimeID, drbg.Uint64(), fmt.Sprintf("%d key %d", i, i), fmt.Sprintf("my cp %d: ", i)+largeVal, false, 0); err != nil {
			return err
		}
	}

	sc.Logger.Info("running first late compute worker")

	// Now spin up the first late compute worker and check if it syncs with a checkpoint.
	lateWorker := sc.Net.ComputeWorkers()[3]
	if err = lateWorker.Start(); err != nil {
		return fmt.Errorf("can't start first late compute worker: %w", err)
	}
	if err = lateWorker.WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for first late compute worker to become ready: %w", err)
	}

	sc.Logger.Info("running second late compute worker")

	latest, err := sc.Net.Controller().Consensus.GetBlock(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to fetch latest block: %w", err)
	}

	// Configure state sync for the last compute node.
	lateWorker = sc.Net.ComputeWorkers()[4]
	lateWorker.SetConsensusStateSync(&oasis.ConsensusStateSyncCfg{
		TrustHeight: uint64(latest.Height),
		TrustHash:   latest.Hash.Hex(),
	})

	if err = lateWorker.Start(); err != nil {
		return fmt.Errorf("can't start second late compute worker: %w", err)
	}
	if err = lateWorker.WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for second late compute worker to become ready: %w", err)
	}

	ctrl, err = oasis.NewController(lateWorker.SocketPath())
	if err != nil {
		return err
	}

	// Ensure that LastRetainedRound returned by GetStatus has corresponding storage.
	status, err := ctrl.GetStatus(ctx)
	if err != nil {
		return fmt.Errorf("error getting status for second late compute worker: %w", err)
	}
	lr := status.Runtimes[KeyValueRuntimeID].LastRetainedRound

	_, err = ctrl.RuntimeClient.GetTransactions(ctx, &runtimeClient.GetTransactionsRequest{
		RuntimeID: KeyValueRuntimeID,
		Round:     lr,
	})
	if err != nil {
		return fmt.Errorf("failed to get last retained block transactions: %w", err)
	}

	// Wait a bit to give the logger in the node time to sync; the message has already been
	// logged by this point, it just might not be on disk yet.
	<-time.After(1 * time.Second)

	return sc.Net.CheckLogWatchers()
}
