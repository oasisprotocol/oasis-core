package runtime

import (
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
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
			[]string{"--mode", "part1"},
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
	if err = sc.DumpRestoreNetwork(childEnv, fixture, true, sc.mapGenesisDocumentFn); err != nil {
		return err
	}

	// Check that everything works with restored state.
	sc.runtimeImpl.clientArgs = []string{"--mode", "part2"}
	return sc.runtimeImpl.Run(childEnv)
}
