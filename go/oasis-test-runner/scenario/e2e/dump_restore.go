package e2e

import (
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// DumpRestore is the dump and restore scenario.
	DumpRestore scenario.Scenario = newDumpRestoreImpl()
)

type dumpRestoreImpl struct {
	runtimeImpl
}

func newDumpRestoreImpl() scenario.Scenario {
	sc := &dumpRestoreImpl{
		runtimeImpl: *newRuntimeImpl(
			"dump-restore",
			"test-long-term-client",
			[]string{"--mode", "part1"},
		),
	}
	return sc
}

func (sc *dumpRestoreImpl) Clone() scenario.Scenario {
	return &dumpRestoreImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *dumpRestoreImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.runtimeImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	select {
	case err = <-sc.runtimeImpl.net.Errors():
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
	if err = sc.dumpRestoreNetwork(childEnv, fixture, true); err != nil {
		return err
	}

	// Check that everything works with restored state.
	sc.runtimeImpl.clientArgs = []string{"--mode", "part2"}
	return sc.runtimeImpl.Run(childEnv)
}
