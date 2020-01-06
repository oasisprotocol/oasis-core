package e2e

import (
	"fmt"
	"path/filepath"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
)

var (
	// DumpRestore is the dump and restore scenario.
	DumpRestore scenario.Scenario = newDumpRestoreImpl()
)

type dumpRestoreImpl struct {
	basicImpl

	logger *logging.Logger
}

func newDumpRestoreImpl() scenario.Scenario {
	sc := &dumpRestoreImpl{
		basicImpl: basicImpl{
			clientBinary: "test-long-term-client",
			clientArgs:   []string{"--mode", "part1"},
		},
		logger: logging.GetLogger("scenario/e2e/dump_restore"),
	}
	return sc
}

func (sc *dumpRestoreImpl) Name() string {
	return "dump-restore"
}

func (sc *dumpRestoreImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.basicImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	select {
	case err = <-sc.basicImpl.net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}
	if err != nil {
		return err
	}

	// Dump state.
	sc.logger.Info("dumping state")

	dumpPath := filepath.Join(childEnv.Dir(), "genesis_dump.json")
	args := []string{
		"genesis", "dump",
		"--height", "0",
		"--genesis.file", dumpPath,
		"--address", "unix:" + sc.basicImpl.net.Validators()[0].SocketPath(),
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "genesis-dump", sc.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to dump state: %w", err)
	}

	// Stop the network.
	sc.logger.Info("stopping the network")
	sc.basicImpl.net.Stop()

	// Dump storage.
	args = []string{
		"debug", "storage", "export",
		"--genesis.file", dumpPath,
		"--datadir", sc.basicImpl.net.StorageWorkers()[0].DataDir(),
		"--storage.export.dir", filepath.Join(childEnv.Dir(), "storage_dumps"),
		"--debug.dont_blame_oasis",
		"--debug.allow_test_keys",
	}
	if err = cli.RunSubCommand(childEnv, sc.logger, "storage-dump", sc.basicImpl.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to dump storage: %w", err)
	}

	// Reset all the state back to the vanilla state.
	if err = sc.basicImpl.cleanTendermintStorage(childEnv); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to clean tendemint storage: %w", err)
	}

	// Start the network and the client again and check that everything
	// works with restored state.
	sc.logger.Info("starting the network again")

	fixture, err := sc.Fixture()
	if err != nil {
		return err
	}

	// Use the dumped genesis file.
	fixture.Network.GenesisFile = dumpPath
	// Make sure to not overwrite the entity.
	fixture.Entities[1].Restore = true

	if sc.basicImpl.net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	sc.basicImpl.clientArgs = []string{"--mode", "part2"}
	return sc.basicImpl.Run(childEnv)
}
