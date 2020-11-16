package runtime

import (
	"context"
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
)

// StorageSyncFromRegistered is the storage sync scenario which tests syncing
// from registered nodes not in committee.
var StorageSyncFromRegistered scenario.Scenario = newStorageSyncFromRegisteredImpl()

type storageSyncFromRegisteredImpl struct {
	runtimeImpl
}

func newStorageSyncFromRegisteredImpl() scenario.Scenario {
	return &storageSyncFromRegisteredImpl{
		runtimeImpl: *newRuntimeImpl(
			"storage-sync-registered",
			"simple-keyvalue-enc-client",
			nil,
		),
	}
}

func (sc *storageSyncFromRegisteredImpl) Clone() scenario.Scenario {
	return &storageSyncFromRegisteredImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *storageSyncFromRegisteredImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Use mock epochtime and small group size so we can control which node will
	// be in the committee.
	f.Network.EpochtimeMock = true
	f.Runtimes[1].Storage.GroupSize = 1
	f.Runtimes[1].Storage.MinPoolSize = f.Runtimes[1].Storage.GroupSize
	f.Runtimes[1].Storage.MinWriteReplication = 1

	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 1
	f.Runtimes[1].Storage.CheckpointChunkSize = 1 * 1024

	// Start only a single node.
	f.StorageWorkers = []oasis.StorageWorkerFixture{
		{
			Backend:                 database.BackendNameBadgerDB,
			Entity:                  1,
			CheckpointCheckInterval: 1 * time.Second,
			AllowEarlyTermination:   true,
		},
		{
			Backend:               database.BackendNameBadgerDB,
			Entity:                1,
			NoAutoStart:           true,
			CheckpointSyncEnabled: true,
		},
	}

	return f, nil
}

func (sc *storageSyncFromRegisteredImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	var nextEpoch epochtime.EpochTime

	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}
	// We're at epoch 2 after the initial transitions
	nextEpoch = epochtime.EpochTime(3)

	// Wait for the client to exit.
	if err = sc.waitClient(childEnv, cmd, clientErrCh); err != nil {
		return err
	}

	sc.Logger.Info("stopping storage worker 0")
	// Shutdown the first storage worker.
	storage0 := sc.Net.StorageWorkers()[0]
	if err = storage0.Stop(); err != nil {
		return fmt.Errorf("storage worker 0 shutdown: %w", err)
	}

	sc.Logger.Info("waiting for storage worker 0 to de-register")

	// Do three epoch transitions so that the node de-registers.
	if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
		return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
	}
	nextEpoch++
	if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
		return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
	}
	nextEpoch++
	if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
		return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
	}
	nextEpoch++
	if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
		return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
	}
	nextEpoch++

	sc.Logger.Info("ensuring no registered storage workers")
	// Ensure there is no registered storage workers.
	nodes, err := sc.Net.Controller().Registry.GetNodes(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}
	for _, n := range nodes {
		if n.HasRoles(node.RoleStorageWorker) {
			return fmt.Errorf("expected no registered storage workers")
		}
	}

	sc.Logger.Info("starting storage worker 1")
	// Start the second Storage worker.
	// XXX: currently 2nd worker will give up on syncing from checkpoints since
	// the other node will be offline. Once this is fixed ensure it syncs from
	// checkpoints.
	storage1 := sc.Net.StorageWorkers()[1]
	err = storage1.Start()
	if err != nil {
		return fmt.Errorf("can't start storage worker 1: %w", err)
	}

	sc.Logger.Info("waiting for storage worker 1 to register")
	// Wait that the storage worker is registered.
	if err = sc.Net.Controller().WaitNodesRegistered(ctx, sc.Net.NumRegisterNodes()-1); err != nil {
		return err
	}

	sc.Logger.Info("ensuring storage worker 1 is elected in committee")
	// Another epoch transition so node is elected into storage committee.
	if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
		return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
	}

	sc.Logger.Info("starting again storage worker 0")
	// Start back the storage 0 so it registers and storage worker 1 can sync.
	err = storage0.Start()
	if err != nil {
		return fmt.Errorf("can't start storage worker 0: %w", err)
	}

	// Wait that storage worker 1 syncs.
	sc.Logger.Info("waiting for storage worker 1 to sync from storage worker 0")
	if err = storage1.WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for late storage worker to become ready: %w", err)
	}

	// Run the client again.
	sc.Logger.Info("starting a second client to check if runtime works with storage worker 1")
	sc.runtimeImpl.clientArgs = []string{
		"--key", "key2",
		"--seed", "second_seed",
	}
	cmd, err = sc.startClient(childEnv)
	if err != nil {
		return err
	}
	client2ErrCh := make(chan error)
	go func() {
		client2ErrCh <- cmd.Wait()
	}()
	return sc.wait(childEnv, cmd, client2ErrCh)
}
