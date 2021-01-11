package runtime

import (
	"context"
	"fmt"

	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// DumpRestore is the dump and restore scenario.
	DumpRestore scenario.Scenario = newDumpRestoreImpl("dump-restore", nil)

	// DumpRestoreRuntimeRoundAdvance is the scenario where additional rounds are simulated after
	// the runtime stopped in the old network (so storage node state is behind).
	DumpRestoreRuntimeRoundAdvance scenario.Scenario = newDumpRestoreImpl(
		"dump-restore/runtime-round-advance",
		func(doc *genesis.Document) {
			// Make it look like there were additional rounds (e.g. from epoch transitions) after the
			// runtime stopped in the old network.
			for _, st := range doc.RootHash.RuntimeStates {
				st.Round += 10
			}
		},
	)
)

type dumpRestoreImpl struct {
	runtimeImpl

	mapGenesisDocumentFn func(*genesis.Document)
}

func newDumpRestoreImpl(
	name string,
	mapGenesisDocumentFn func(*genesis.Document),
) scenario.Scenario {
	sc := &dumpRestoreImpl{
		runtimeImpl: *newRuntimeImpl(
			name,
			"test-long-term-client",
			// Use -nomsg variant as this test also compares with the database dump which cannot
			// reconstruct the emitted messages as those are not available in the state dump alone.
			[]string{"--mode", "part1-nomsg"},
		),
		mapGenesisDocumentFn: mapGenesisDocumentFn,
	}
	return sc
}

func (sc *dumpRestoreImpl) Clone() scenario.Scenario {
	return &dumpRestoreImpl{
		runtimeImpl:          *sc.runtimeImpl.Clone().(*runtimeImpl),
		mapGenesisDocumentFn: sc.mapGenesisDocumentFn,
	}
}

func (sc *dumpRestoreImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.runtimeImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Configure runtime for storage checkpointing.
	f.Runtimes[1].Storage.CheckpointInterval = 10
	f.Runtimes[1].Storage.CheckpointNumKept = 1
	f.Runtimes[1].Storage.CheckpointChunkSize = 1 * 1024

	return f, nil
}

func (sc *dumpRestoreImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.start(childEnv)
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

	// Dump restore network.
	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Completely reset state for one of the storage nodes so we can test initial sync.
	sc.Logger.Info("completely resetting state for one of the storage nodes")
	cli := cli.New(childEnv, sc.Net, sc.Logger)
	if err = cli.UnsafeReset(sc.Net.StorageWorkers()[1].DataDir(), false, false); err != nil {
		return fmt.Errorf("failed to reset state for storage worker: %w", err)
	}

	if err = sc.DumpRestoreNetwork(childEnv, fixture, true, sc.mapGenesisDocumentFn); err != nil {
		return err
	}
	if err = sc.Net.Start(); err != nil {
		return fmt.Errorf("failed to start restored network: %w", err)
	}

	// Wait for all storage and compute nodes to be ready.
	ctx := context.Background()
	sc.Logger.Info("waiting for all storage and compute nodes to be ready")
	for _, n := range sc.Net.StorageWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a storage worker: %w", err)
		}
	}
	for _, n := range sc.Net.ComputeWorkers() {
		if err = n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Check that everything works with restored state.
	sc.runtimeImpl.clientArgs = []string{
		"--mode", "part2",
		// Use a different nonce seed.
		"--seed", "second_seed",
	}
	return sc.runtimeImpl.Run(childEnv)
}
