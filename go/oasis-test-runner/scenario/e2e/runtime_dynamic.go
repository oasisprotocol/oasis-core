package e2e

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var (
	// RuntimeDynamic is the dynamic runtime registration scenario.
	RuntimeDynamic scenario.Scenario = newRuntimeDynamicImpl()
)

type runtimeDynamicImpl struct {
	basicImpl

	epoch epochtime.EpochTime
}

func newRuntimeDynamicImpl() scenario.Scenario {
	return &runtimeDynamicImpl{
		basicImpl: *newBasicImpl("runtime-dynamic", "", nil),
	}
}

func (sc *runtimeDynamicImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// We need IAS proxy to use the registry as we are registering runtimes dynamically.
	f.Network.IASUseRegistry = true
	// Avoid unexpected blocks.
	f.Network.EpochtimeMock = true
	// We need runtime registration to be enabled.
	// TODO: This should not be needed once this is the default (no longer debug).
	f.Network.RegistryDebugAllowRuntimeRegistration = true
	// Exclude all runtimes from genesis as we will register those dynamically.
	for i, rt := range f.Runtimes {
		// TODO: This should not be needed once dynamic keymanager policy document registration
		//       is supported (see oasis-core#2516).
		if rt.Kind != registry.KindCompute {
			continue
		}
		f.Runtimes[i].ExcludeFromGenesis = true
	}
	// All runtime nodes should be restartable as we are going to restart them.
	for i := range f.StorageWorkers {
		f.StorageWorkers[i].Restartable = true
	}
	for i := range f.ComputeWorkers {
		f.ComputeWorkers[i].Restartable = true
	}

	return f, nil
}

func (sc *runtimeDynamicImpl) epochTransition(ctx context.Context) error {
	sc.epoch++

	sc.logger.Info("triggering epoch transition",
		"epoch", sc.epoch,
	)
	if err := sc.net.Controller().SetEpoch(ctx, sc.epoch); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.logger.Info("epoch transition done")
	return nil
}

func (sc *runtimeDynamicImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return err
	}

	ctx := context.Background()
	cli := cli.New(childEnv, sc.net, sc.logger)

	// Wait for all nodes to be synced before we proceed.
	if err := sc.waitNodesSynced(); err != nil {
		return err
	}

	// TODO: Once dynamic key manager registration is supported, waiting for keymanagers
	// shouldn't be needed.
	numNodes := len(sc.net.Validators()) + len(sc.net.Keymanagers())
	sc.logger.Info("waiting for (some) nodes to register",
		"num_nodes", numNodes,
	)
	if err := sc.net.Controller().WaitNodesRegistered(ctx, numNodes); err != nil {
		return err
	}

	// Perform an initial epoch transition to make sure that the nodes can handle it even though
	// there are no runtimes registered yet.
	if err := sc.epochTransition(ctx); err != nil {
		return err
	}

	// TODO: Register a new key manager runtime and status (see oasis-core#2516).

	// Register a new compute runtime.
	compRt := sc.net.Runtimes()[1].ToRuntimeDescriptor()
	txPath := filepath.Join(childEnv.Dir(), "register_compute_runtime.json")
	if err := cli.Registry.GenerateRegisterRuntimeTx(0, compRt, txPath, ""); err != nil {
		return fmt.Errorf("failed to generate register runtime tx: %w", err)
	}
	if err := cli.Consensus.SubmitTx(txPath); err != nil {
		return fmt.Errorf("failed to register compute runtime: %w", err)
	}

	// Wait for all nodes to register.
	sc.logger.Info("waiting for runtime nodes to register",
		"num_nodes", sc.net.NumRegisterNodes(),
	)
	if err := sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return err
	}

	for i := 0; i < 5; i++ {
		// Perform another epoch transition to elect compute runtime committees.
		if err := sc.epochTransition(ctx); err != nil {
			return err
		}

		// Wait a bit after epoch transitions.
		time.Sleep(1 * time.Second)

		// Submit a runtime transaction.
		sc.logger.Info("submitting transaction to runtime",
			"seq", i,
		)
		if err := sc.submitRuntimeTx(ctx, runtimeID, "hello", fmt.Sprintf("world %d", i)); err != nil {
			return err
		}
	}

	// Stop all runtime nodes, so they will not re-register, causing the nodes to expire.
	sc.logger.Info("stopping storage nodes")
	for _, n := range sc.net.StorageWorkers() {
		if err := n.Stop(); err != nil {
			return fmt.Errorf("failed to stop node: %w", err)
		}
	}
	sc.logger.Info("stopping compute nodes")
	for _, n := range sc.net.ComputeWorkers() {
		if err := n.Stop(); err != nil {
			return fmt.Errorf("failed to stop node: %w", err)
		}
	}

	// Epoch transitions so nodes expire.
	sc.logger.Info("performing epoch transitions so nodes expire")
	for i := 0; i < 3; i++ {
		if err := sc.epochTransition(ctx); err != nil {
			return err
		}

		// Wait a bit between epoch transitions.
		time.Sleep(1 * time.Second)
	}

	// Ensure that runtime got suspended.
	sc.logger.Info("checking that runtime got suspended")
	_, err := sc.net.Controller().Registry.GetRuntime(ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     compRt.ID,
	})
	switch err {
	case nil:
		return fmt.Errorf("runtime should be suspended but it is not")
	case registry.ErrNoSuchRuntime:
		// Runtime is suspended.
	default:
		return fmt.Errorf("unexpected error while fetching runtime: %w", err)
	}

	// Start runtime nodes, make sure they register.
	sc.logger.Info("starting storage nodes")
	for _, n := range sc.net.StorageWorkers() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}
	sc.logger.Info("starting compute nodes")
	for _, n := range sc.net.ComputeWorkers() {
		if err := n.Start(); err != nil {
			return fmt.Errorf("failed to start node: %w", err)
		}
	}

	sc.logger.Info("waiting for runtime nodes to register",
		"num_nodes", sc.net.NumRegisterNodes(),
	)
	if err := sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return err
	}

	// Epoch transition.
	if err := sc.epochTransition(ctx); err != nil {
		return err
	}

	// Submit a runtime transaction to check whether the runtimes got resumed.
	sc.logger.Info("submitting transaction to runtime")
	if err := sc.submitRuntimeTx(ctx, runtimeID, "hello", "final world"); err != nil {
		return err
	}

	return nil
}
