package runtime

import (
	"context"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// StorageSyncFromRegistered is the storage sync scenario which tests syncing
// from registered nodes not in committee.
var StorageSyncFromRegistered scenario.Scenario = newStorageSyncFromRegisteredImpl()

type storageSyncFromRegisteredImpl struct {
	runtimeImpl
}

func newStorageSyncFromRegisteredImpl() scenario.Scenario {
	return &storageSyncFromRegisteredImpl{
		runtimeImpl: *newRuntimeImpl("storage-sync-registered", BasicKVEncTestClient),
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
	f.Network.SetMockEpoch()
	f.Runtimes[1].Executor.GroupSize = 1
	f.Runtimes[1].Constraints[scheduler.KindComputeExecutor][scheduler.RoleWorker].MinPoolSize.Limit = 1

	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 1
	f.Runtimes[1].Storage.CheckpointChunkSize = 1 * 1024

	// Start only a single node.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{
		{
			Entity:                  1,
			Runtimes:                []int{1},
			CheckpointCheckInterval: 1 * time.Second,
			AllowEarlyTermination:   true,
		},
		{
			NodeFixture: oasis.NodeFixture{
				NoAutoStart: true,
			},
			Entity:                1,
			Runtimes:              []int{1},
			CheckpointSyncEnabled: true,
		},
	}

	return f, nil
}

func (sc *storageSyncFromRegisteredImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	var nextEpoch beacon.EpochTime

	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	if nextEpoch, err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}
	nextEpoch++

	// Wait for the client to exit.
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	sc.Logger.Info("stopping compute worker 0")
	// Shutdown the first compute worker.
	compute0 := sc.Net.ComputeWorkers()[0]
	if err = compute0.Stop(); err != nil {
		return fmt.Errorf("compute worker 0 shutdown: %w", err)
	}

	sc.Logger.Info("waiting for compute worker 0 to de-register")

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

	sc.Logger.Info("ensuring no registered compute workers")
	// Ensure there is no registered compute workers.
	nodes, err := sc.Net.Controller().Registry.GetNodes(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get nodes: %w", err)
	}
	for _, n := range nodes {
		if n.HasRoles(node.RoleComputeWorker) {
			return fmt.Errorf("expected no registered compute workers")
		}
	}

	sc.Logger.Info("starting compute worker 1")
	// Start the second compute worker.
	// XXX: currently 2nd worker will give up on syncing from checkpoints since
	// the other node will be offline. Once this is fixed ensure it syncs from
	// checkpoints.
	compute1 := sc.Net.ComputeWorkers()[1]
	err = compute1.Start()
	if err != nil {
		return fmt.Errorf("can't start compute worker 1: %w", err)
	}

	sc.Logger.Info("starting again compute worker 0")
	// Start back the compute 0 so it registers and compute worker 1 can sync.
	err = compute0.Start()
	if err != nil {
		return fmt.Errorf("can't start compute worker 0: %w", err)
	}

	// Wait that compute worker 1 syncs.
	sc.Logger.Info("waiting for compute worker 1 to sync from compute worker 0")
	if err = compute1.WaitReady(ctx); err != nil {
		return fmt.Errorf("error waiting for late compute worker to become ready: %w", err)
	}

	sc.Logger.Info("waiting for compute worker 1 to register")
	// Wait that the compute worker is registered.
	if err = sc.Net.Controller().WaitNodesRegistered(ctx, sc.Net.NumRegisterNodes()-1); err != nil {
		return err
	}

	sc.Logger.Info("ensuring compute worker 1 is elected in committee")
	// Another epoch transition so node is elected into compute committee.
	if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
		return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
	}
	nextEpoch++

	sc.Logger.Info("ensuring compute worker 1 REALLY is elected in committee")
	// Another epoch transition so node is REALLY elected into compute committee
	// and hopefully not blocked by the beacon lockout.
	if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
		return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
	}

	// Run the client again.
	sc.Logger.Info("starting a second client to check if runtime works with compute worker 1")
	newTestClient := sc.testClient.Clone().(*KeyValueEncTestClient)
	sc.runtimeImpl.testClient = newTestClient.WithKey("key2").WithSeed("second_seed")
	if err = sc.startTestClientOnly(ctx, childEnv); err != nil {
		return err
	}
	return sc.waitTestClient()
}
