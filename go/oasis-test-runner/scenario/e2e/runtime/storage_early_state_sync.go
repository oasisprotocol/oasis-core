package runtime

import (
	"context"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// StorageEarlyStateSync is the scenario where a runtime is registered first and is not yet
// operational, then a while later an executor node uses consensus layer state sync to catch up but
// the runtime has already advanced some epoch transition rounds and is no longer at genesis.
var StorageEarlyStateSync scenario.Scenario = newStorageEarlyStateSyncImpl()

type storageEarlyStateSyncImpl struct {
	Scenario

	epoch beacon.EpochTime
}

func newStorageEarlyStateSyncImpl() scenario.Scenario {
	return &storageEarlyStateSyncImpl{
		Scenario: *NewScenario("storage-early-state-sync", nil),
	}
}

func (sc *storageEarlyStateSyncImpl) Clone() scenario.Scenario {
	return &storageEarlyStateSyncImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
		epoch:    sc.epoch,
	}
}

func (sc *storageEarlyStateSyncImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Allocate stake and set runtime thresholds.
	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			Thresholds: map[staking.ThresholdKind]quantity.Quantity{
				staking.KindEntity:            *quantity.NewFromUint64(0),
				staking.KindNodeValidator:     *quantity.NewFromUint64(0),
				staking.KindNodeCompute:       *quantity.NewFromUint64(0),
				staking.KindNodeObserver:      *quantity.NewFromUint64(0),
				staking.KindNodeKeyManager:    *quantity.NewFromUint64(0),
				staking.KindRuntimeCompute:    *quantity.NewFromUint64(1000),
				staking.KindRuntimeKeyManager: *quantity.NewFromUint64(1000),
			},
		},
	}
	// Enable consensus layer checkpoints.
	f.Network.Consensus.Parameters.StateCheckpointInterval = 10
	f.Network.Consensus.Parameters.StateCheckpointNumKept = 2
	f.Network.Consensus.Parameters.StateCheckpointChunkSize = 1024 * 1024
	// No need for key managers.
	f.Runtimes = f.Runtimes[1:]
	f.Runtimes[0].Keymanager = -1
	f.Keymanagers = nil
	f.KeymanagerPolicies = nil
	// No need for clients (the runtime will not actually fully work as we just want to make sure
	// initialization works correctly).
	f.Clients = nil
	// Exclude runtime from genesis as we will register those dynamically.
	f.Runtimes[0].ExcludeFromGenesis = true
	// Set up compute workers.
	f.ComputeWorkers = []oasis.ComputeWorkerFixture{
		// One compute node that will perform state sync.
		{
			NodeFixture: oasis.NodeFixture{
				NoAutoStart: true,
			},
			Entity:                1,
			CheckpointSyncEnabled: true,
			LogWatcherHandlerFactories: []log.WatcherHandlerFactory{
				oasis.LogEventABCIStateSyncComplete(),
			},
			Runtimes: []int{0},
		},
		// Another compute node that doesn't use state sync to avoid the case where the runtime is
		// suspended forever because no compute node has the current consensus block.
		{
			NodeFixture: oasis.NodeFixture{
				NoAutoStart: true,
			},
			Entity:   1,
			Runtimes: []int{0},
		},
	}

	return f, nil
}

func (sc *storageEarlyStateSyncImpl) Run(ctx context.Context, childEnv *env.Env) error { // nolint: gocyclo
	if err := sc.Net.Start(); err != nil {
		return err
	}

	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Wait for validator nodes to register.
	sc.Logger.Info("waiting for validator nodes to initialize",
		"num_validators", len(sc.Net.Validators()),
	)
	for _, n := range sc.Net.Validators() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a validator: %w", err)
		}
	}

	// Fetch current epoch.
	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get current epoch: %w", err)
	}

	// Register a new compute runtime.
	sc.Logger.Info("registering a new compute runtime")
	compRt := sc.Net.Runtimes()[0]
	compRtDesc := compRt.ToRuntimeDescriptor()
	compRtDesc.Deployments[0].ValidFrom = epoch + 1
	if err = sc.RegisterRuntime(childEnv, cli, compRtDesc, 0); err != nil {
		return err
	}

	// Wait some epoch transitions.
	sc.Logger.Info("waiting some epoch transitions",
		"epoch", epoch+5,
	)
	if err = sc.Net.Controller().Beacon.WaitEpoch(ctx, epoch+5); err != nil {
		return fmt.Errorf("failed to wait for epoch: %w", err)
	}

	// TODO: Make sure we have enough blocks.

	latest, err := sc.Net.Controller().Consensus.GetBlock(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to fetch latest block: %w", err)
	}

	// Start the second (non-state syncing) compute node.
	sc.Logger.Info("starting compute node without state sync")
	if err := sc.Net.ComputeWorkers()[1].Start(); err != nil {
		return fmt.Errorf("can't start compute worker: %w", err)
	}

	// Configure state sync for the compute node.
	sc.Logger.Info("starting compute node with state sync")
	worker := sc.Net.ComputeWorkers()[0]
	worker.SetConsensusStateSync(&oasis.ConsensusStateSyncCfg{
		TrustHeight: uint64(latest.Height),
		TrustHash:   latest.Hash.Hex(),
	})

	if err := worker.Start(); err != nil {
		return fmt.Errorf("can't start compute worker: %w", err)
	}
	readyCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if err := worker.WaitReady(readyCtx); err != nil {
		return fmt.Errorf("error waiting for compute worker to become ready: %w", err)
	}

	// Wait a bit to give the logger in the node time to sync; the message has already been
	// logged by this point, it just might not be on disk yet.
	<-time.After(1 * time.Second)

	return sc.Net.CheckLogWatchers()
}
