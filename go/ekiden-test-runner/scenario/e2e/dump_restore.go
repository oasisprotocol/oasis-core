package e2e

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/scenario"
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
	if err = runSubCommand(childEnv, "genesis-dump", sc.basicImpl.net.Config().EkidenBinary, args); err != nil {
		return errors.Wrap(err, "scenario/e2e/dump_restore: failed to dump state")
	}

	// Stop the network.
	sc.logger.Info("stopping the network")
	sc.basicImpl.net.Stop()

	preservePaths := make(map[string]bool)
	preserveComponents := make(map[string]bool)
	preservePath := func(path string) {
		preservePaths[path] = true

		for len(path) > 1 {
			path = filepath.Clean(path)
			preserveComponents[path] = true
			path, _ = filepath.Split(path)
		}
	}

	// Preserve all identities.
	sc.logger.Debug("preserving identities")
	for _, ent := range sc.basicImpl.net.Entities() {
		preservePath(ent.EntityKeyPath())
		preservePath(ent.DescriptorPath())
	}
	for _, val := range sc.basicImpl.net.Validators() {
		preservePath(val.IdentityKeyPath())
		preservePath(val.P2PKeyPath())
	}
	for _, sw := range sc.basicImpl.net.StorageWorkers() {
		preservePath(sw.IdentityKeyPath())
		preservePath(sw.P2PKeyPath())
		preservePath(sw.TLSKeyPath())
		preservePath(sw.TLSCertPath())
	}
	for _, cw := range sc.basicImpl.net.ComputeWorkers() {
		preservePath(cw.IdentityKeyPath())
		preservePath(cw.P2PKeyPath())
		preservePath(cw.TLSKeyPath())
		preservePath(cw.TLSCertPath())
	}
	km := sc.basicImpl.net.Keymanager()
	preservePath(km.IdentityKeyPath())
	preservePath(km.P2PKeyPath())
	preservePath(km.TLSKeyPath())
	preservePath(km.TLSCertPath())
	// Preserve key manager state.
	preservePath(km.LocalStoragePath())

	// Preserve storage.
	sc.logger.Debug("preserving storage")
	for _, sw := range sc.basicImpl.net.StorageWorkers() {
		sc.logger.Debug("preserving storage database",
			"path", sw.DatabasePath(),
		)
		preservePath(sw.DatabasePath())
	}

	// Remove all files except what should be preserved.
	err = filepath.Walk(sc.basicImpl.net.BasePath(), func(path string, info os.FileInfo, fErr error) error {
		// Preserve everything under a path.
		if preservePaths[path] {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Also preserve any components of paths.
		if preserveComponents[path] {
			return nil
		}
		// Remove everything else.
		sc.logger.Debug("removing path",
			"path", path,
		)
		if err = os.RemoveAll(path); err != nil {
			return err
		}
		if info.IsDir() {
			// No need to recurse into directory as it has been removed.
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return err
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
