package e2e

import (
	"context"
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
	"github.com/oasislabs/oasis-core/go/storage/database"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/checkpoint"
)

var (
	// StorageSync is the storage sync scenario.
	StorageSync scenario.Scenario = newStorageSyncImpl()
)

type storageSyncImpl struct {
	basicImpl
}

func newStorageSyncImpl() scenario.Scenario {
	return &storageSyncImpl{
		basicImpl: *newBasicImpl("storage-sync", "simple-keyvalue-client", nil),
	}
}

func (sc *storageSyncImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Make the first storage worker check for checkpoints more often.
	f.StorageWorkers[0].CheckpointCheckInterval = 1 * time.Second
	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 1
	f.Runtimes[1].Storage.CheckpointChunkSize = 1024 * 1024
	// Provision another storage node and make it ignore all applies.
	f.StorageWorkers = append(f.StorageWorkers, oasis.StorageWorkerFixture{
		Backend:       database.BackendNameBadgerDB,
		Entity:        1,
		IgnoreApplies: true,
	})
	return f, nil
}

func (sc *storageSyncImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.basicImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	if err = sc.wait(childEnv, cmd, clientErrCh); err != nil {
		return err
	}

	// Check if the storage node that ignored applies has synced.
	sc.logger.Info("checking if roots have been synced")

	storageNode := sc.basicImpl.net.StorageWorkers()[2]
	args := []string{
		"debug", "storage", "check-roots",
		"--log.level", "debug",
		"--address", "unix:" + storageNode.SocketPath(),
		sc.basicImpl.net.Runtimes()[1].ID().String(),
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "storage-check-roots", sc.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("root check failed after sync: %w", err)
	}

	// Generate some more rounds to trigger checkpointing. Up to this point there have been ~9
	// rounds, we create 15 more rounds to bring this up to ~24. Checkpoints are every 10 rounds so
	// this leaves some space for any unintended epoch transitions.
	ctx := context.Background()
	for i := 0; i < 15; i++ {
		sc.logger.Info("submitting transaction to runtime",
			"seq", i,
		)
		if err = sc.submitRuntimeTx(ctx, runtimeID, "checkpoint", fmt.Sprintf("my cp %d", i)); err != nil {
			return err
		}
	}

	// Make sure that the first storage node created checkpoints.
	ctrl, err := oasis.NewController(sc.net.StorageWorkers()[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to connect with the first storage node: %w", err)
	}

	cps, err := ctrl.Storage.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1, Namespace: runtimeID})
	if err != nil {
		return fmt.Errorf("failed to get checkpoints: %w", err)
	}

	blk, err := ctrl.RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
		RuntimeID: runtimeID,
		Round:     runtimeClient.RoundLatest,
	})
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	// Determine which checkpoints should be there.
	rt := sc.net.Runtimes()[1].ToRuntimeDescriptor()
	lastCheckpoint := (blk.Header.Round / rt.Storage.CheckpointInterval) * rt.Storage.CheckpointInterval
	sc.logger.Info("determined last expected checkpoint round",
		"round", lastCheckpoint,
	)

	// There should be at least two checkpoints. There may be more depending on the state of garbage
	// collection process (which may be one checkpoint behind.)
	if len(cps) < 2 {
		return fmt.Errorf("incorrect number of checkpoints (expected: >=2 got: %d)", len(cps))
	}

	var validCps int
	for checkpoint := rt.Storage.CheckpointInterval; checkpoint <= lastCheckpoint; checkpoint += rt.Storage.CheckpointInterval {
		blk, err = ctrl.RuntimeClient.GetBlock(ctx, &runtimeClient.GetBlockRequest{
			RuntimeID: runtimeID,
			Round:     checkpoint,
		})
		if err != nil {
			return fmt.Errorf("failed to get block %d: %w", checkpoint, err)
		}
		for _, cp := range cps {
			if cp.Root.Round != blk.Header.Round {
				continue
			}
			var found bool
			for _, root := range blk.Header.StorageRoots() {
				if root.Equal(&cp.Root) {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("checkpoint for unexpected root %s", cp.Root)
			}
			sc.logger.Info("found valid checkpoint",
				"round", checkpoint,
				"root_hash", cp.Root.Hash,
			)
			validCps++
		}
	}
	if validCps < 2 {
		return fmt.Errorf("incorrect number of valid checkpoints (expected: >=2 got: %d)", validCps)
	}

	return nil
}
