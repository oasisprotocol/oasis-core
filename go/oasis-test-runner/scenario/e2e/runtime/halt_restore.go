package runtime

import (
	"context"
	"fmt"
	"math"
	"reflect"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

var (
	// HaltRestore is the halt and restore scenario.
	HaltRestore scenario.Scenario = newHaltRestoreImpl(false)
	// HaltRestoreSuspended is the halt and restore scenario with a suspended runtime.
	HaltRestoreSuspended scenario.Scenario = newHaltRestoreImpl(true)
)

const haltEpoch = 10

type haltRestoreImpl struct {
	runtimeImpl

	suspendRuntime bool
	haltEpoch      int
}

func newHaltRestoreImpl(suspended bool) scenario.Scenario {
	name := "halt-restore"
	haltEpoch := haltEpoch
	if suspended {
		name += "-suspended"
		// Add some epochs since we're also suspending a runtime.
		haltEpoch += 5
	}
	return &haltRestoreImpl{
		runtimeImpl: *newRuntimeImpl(
			name,
			NewLongTermTestClient().WithMode(ModePart1),
		),
		haltEpoch:      haltEpoch,
		suspendRuntime: suspended,
	}
}

func (sc *haltRestoreImpl) Clone() scenario.Scenario {
	return &haltRestoreImpl{
		runtimeImpl:    *sc.runtimeImpl.Clone().(*runtimeImpl),
		suspendRuntime: sc.suspendRuntime,
		haltEpoch:      sc.haltEpoch,
	}
}

func (sc *haltRestoreImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}
	f.Network.SetMockEpoch()
	f.Network.HaltEpoch = uint64(sc.haltEpoch)
	for _, val := range f.Validators {
		val.AllowEarlyTermination = true
	}
	return f, nil
}

func (sc *haltRestoreImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}
	var nextEpoch beacon.EpochTime
	if nextEpoch, err = sc.initialEpochTransitions(fixture); err != nil {
		return err
	}
	nextEpoch++ // Next, after initial transitions.

	// Wait for the client to exit.
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	if sc.suspendRuntime {
		// Stop compute nodes.
		sc.Logger.Info("stopping compute nodes")
		for _, n := range sc.Net.ComputeWorkers() {
			if err = n.StopGracefully(); err != nil {
				return fmt.Errorf("failed to stop node: %w", err)
			}
		}

		// Epoch transitions so nodes expire.
		sc.Logger.Info("performing epoch transitions so nodes expire")
		for i := 0; i < 3; i++ {

			if err = sc.Net.Controller().SetEpoch(ctx, nextEpoch); err != nil {
				return fmt.Errorf("failed to set epoch %d: %w", nextEpoch, err)
			}
			nextEpoch++
		}

		// Ensure that runtime got suspended.
		sc.Logger.Info("checking that runtime got suspended")
		_, err = sc.Net.Controller().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
			Height: consensus.HeightLatest,
			ID:     fixture.Runtimes[1].ID,
		})
		switch err {
		case nil:
			return fmt.Errorf("runtime should be suspended but it is not")
		case registry.ErrNoSuchRuntime:
			// Runtime is suspended.
			sc.Logger.Info("runtime is suspended")
		default:
			return fmt.Errorf("unexpected error while fetching runtime: %w", err)
		}
	}

	// Transition to halt epoch.
	sc.Logger.Info("transitioning to halt epoch",
		"halt_epoch", sc.haltEpoch,
	)
	for i := nextEpoch; i <= beacon.EpochTime(sc.haltEpoch); i++ {
		sc.Logger.Info("setting epoch",
			"epoch", i,
		)
		if err = sc.Net.Controller().SetEpoch(ctx, i); err != nil {
			return fmt.Errorf("failed to set epoch %d: %w", i, err)
		}
	}

	// Wait for validators to exit so that genesis docs are dumped.
	var exitChs []reflect.SelectCase
	for _, val := range sc.Net.Validators() {
		exitChs = append(exitChs, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(val.Exit()),
		})
	}
	// Exit status doesn't matter, we only need one of the validators to stop existing.
	_, _, _ = reflect.Select(exitChs)

	sc.Logger.Info("gathering exported genesis files")
	files, err := sc.GetExportedGenesisFiles(true)
	if err != nil {
		return fmt.Errorf("failure getting exported genesis files: %w", err)
	}

	// Stop the network.
	sc.Logger.Info("stopping the network")
	sc.Net.Stop()
	if err = sc.ResetConsensusState(childEnv, nil); err != nil {
		return fmt.Errorf("failed to reset consensus state: %w", err)
	}

	// Start the network and the client again and check that everything
	// works with restored state.
	sc.Logger.Info("starting the network again")

	// Update halt epoch in the exported genesis so the network doesn't
	// instantly halt.
	genesisFileProvider, err := genesis.NewFileProvider(files[0])
	if err != nil {
		sc.Logger.Error("failed getting genesis file provider",
			"err", err,
			"genesis_file", files[0],
		)
		return err
	}
	genesisDoc, err := genesisFileProvider.GetGenesisDocument()
	if err != nil {
		sc.Logger.Error("failed getting genesis document from file provider",
			"err", err,
		)
		return err
	}
	genesisDoc.HaltEpoch = math.MaxUint64
	if err = genesisDoc.WriteFileJSON(files[0]); err != nil {
		sc.Logger.Error("failed to update genesis",
			"err", err,
		)
		return err
	}

	// Ensure compute runtime in genesis is in expected state.
	var rtList []*registry.Runtime
	switch sc.suspendRuntime {
	case true:
		rtList = genesisDoc.Registry.SuspendedRuntimes
	default:
		rtList = genesisDoc.Registry.Runtimes
	}
	var found bool
	for _, rt := range rtList {
		if rt.Kind != registry.KindCompute {
			continue
		}
		found = true
	}
	if !found {
		sc.Logger.Error("runtime not in expected state",
			"expected_suspended", sc.suspendRuntime,
			"runtimes", genesisDoc.Registry.Runtimes,
			"suspended_runtimes", genesisDoc.Registry.SuspendedRuntimes,
		)
		return fmt.Errorf("runtime not in expected state")
	}

	// Use the updated genesis file.
	fixture.Network.GenesisFile = files[0]
	// Make sure to not overwrite the entity.
	fixture.Entities[1].Restore = true

	if sc.Net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	// If network is used, enable shorter per-node socket paths, because some e2e test datadir exceed maximum unix
	// socket path length.
	sc.Net.Config().UseShortGrpcSocketPaths = true

	newTestClient := sc.testClient.Clone().(*LongTermTestClient)
	sc.runtimeImpl.testClient = newTestClient.WithMode(ModePart2).WithSeed("second_seed")

	// Start the new network again and run the test client.
	if err = sc.startNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}
	if _, err = sc.initialEpochTransitionsWith(fixture, genesisDoc.Beacon.Base); err != nil {
		return err
	}
	if err = sc.startTestClientOnly(ctx, childEnv); err != nil {
		return err
	}
	return sc.waitTestClientOnly()
}
