package runtime

import (
	"context"
	"fmt"
	"math"
	"reflect"

	genesis "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// HaltRestoreNonMock is the halt and restore scenario that uses the real beacon backend.
var HaltRestoreNonMock scenario.Scenario = newHaltRestoreNonMockImpl()

type haltRestoreNonMockImpl struct {
	runtimeImpl

	haltEpoch int
}

func newHaltRestoreNonMockImpl() scenario.Scenario {
	name := "halt-restore-nonmock"
	return &haltRestoreNonMockImpl{
		runtimeImpl: *newRuntimeImpl(
			name,
			NewLongTermTestClient().WithMode(ModePart1),
		),
		haltEpoch: 8,
	}
}

func (sc *haltRestoreNonMockImpl) Clone() scenario.Scenario {
	return &haltRestoreNonMockImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
		haltEpoch:   sc.haltEpoch,
	}
}

func (sc *haltRestoreNonMockImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}
	f.Network.HaltEpoch = uint64(sc.haltEpoch)
	for _, val := range f.Validators {
		val.AllowEarlyTermination = true
	}
	return f, nil
}

func (sc *haltRestoreNonMockImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	if err = sc.waitTestClientOnly(); err != nil {
		return err
	}

	sc.Logger.Info("waiting for the network to stop")

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
	genesisDoc.Beacon.Parameters.VRFParameters.Interval -= 5 // Reduce interval.
	if err = genesisDoc.WriteFileJSON(files[0]); err != nil {
		sc.Logger.Error("failed to update genesis",
			"err", err,
		)
		return err
	}

	// Use the updated genesis file.
	fixture.Network.GenesisFile = files[0]
	// Make sure to not overwrite the entity.
	fixture.Entities[1].Restore = true

	if sc.Net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	// If network is used, enable shorter per-node socket paths, because some e2e test datadir
	// exceed maximum unix socket path length.
	sc.Net.Config().UseShortGrpcSocketPaths = true

	newTestClient := sc.testClient.Clone().(*LongTermTestClient)
	sc.runtimeImpl.testClient = newTestClient.WithMode(ModePart2).WithSeed("second_seed")

	// Start the new network again and run the test client.
	if err = sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}
	return sc.waitTestClientOnly()
}
