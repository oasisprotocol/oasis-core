package runtime

import (
	"context"
	"fmt"
	"reflect"

	genesis "github.com/oasisprotocol/oasis-core/go/genesis/file"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// HaltRestore is the halt and restore scenario.
var HaltRestore scenario.Scenario = newHaltRestoreImpl()

const haltEpoch = 3

type haltRestoreImpl struct {
	runtimeImpl
}

func newHaltRestoreImpl() scenario.Scenario {
	return &haltRestoreImpl{
		runtimeImpl: *newRuntimeImpl(
			"halt-restore",
			"test-long-term-client",
			[]string{"--mode", "part1"},
		),
	}
}

func (sc *haltRestoreImpl) Clone() scenario.Scenario {
	return &haltRestoreImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *haltRestoreImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}
	f.Network.HaltEpoch = haltEpoch
	for _, val := range f.Validators {
		val.AllowEarlyTermination = true
	}
	return f, nil
}

func (sc *haltRestoreImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	select {
	case err = <-sc.Net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}
	if err != nil {
		return err
	}

	// Wait for the epoch after the halt epoch.
	ctx := context.Background()
	sc.Logger.Info("waiting for halt epoch")
	// Wait for halt epoch.
	err = sc.Net.Controller().Consensus.WaitEpoch(ctx, haltEpoch)
	if err != nil {
		return fmt.Errorf("failed waiting for halt epoch: %w", err)
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
	files, err := sc.GetExportedGenesisFiles()
	if err != nil {
		return fmt.Errorf("failure getting exported genesis files: %w", err)
	}

	// Stop the network.
	sc.Logger.Info("stopping the network")
	sc.Net.Stop()
	if err = sc.ResetConsensusState(childEnv); err != nil {
		return fmt.Errorf("failed to reset consensus state: %w", err)
	}

	// Start the network and the client again and check that everything
	// works with restored state.
	sc.Logger.Info("starting the network again")

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

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
	genesisDoc.HaltEpoch = 2 * haltEpoch
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

	// If network is used, enable shorter per-node socket paths, because some e2e test datadir exceed maximum unix
	// socket path length.
	sc.Net.Config().UseShortGrpcSocketPaths = true

	sc.runtimeImpl.clientArgs = []string{"--mode", "part2"}
	return sc.runtimeImpl.Run(childEnv)
}
