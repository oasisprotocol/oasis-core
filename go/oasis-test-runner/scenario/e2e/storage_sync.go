package e2e

import (
	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasislabs/oasis-core/go/storage/database"
)

var (
	// StorageSync is the storage sync scenario.
	StorageSync scenario.Scenario = newStorageSyncImpl()
)

type storageSyncImpl struct {
	basicImpl

	logger *logging.Logger
}

func newStorageSyncImpl() scenario.Scenario {
	sc := &storageSyncImpl{
		basicImpl: basicImpl{
			clientBinary: "simple-keyvalue-client",
		},
		logger: logging.GetLogger("scenario/e2e/storage_sync"),
	}
	return sc
}

func (sc *storageSyncImpl) Name() string {
	return "storage-sync"
}

func (sc *storageSyncImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.basicImpl.Fixture()
	if err != nil {
		return nil, err
	}

	// Provision another storage node and make it ignore all applies.
	f.StorageWorkers = append(f.StorageWorkers, oasis.StorageWorkerFixture{
		Backend:       database.BackendNameBadgerDB,
		Entity:        1,
		IgnoreApplies: true,
	})
	return f, nil
}

func (sc *storageSyncImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.basicImpl.start(childEnv)
	if err != nil {
		return err
	}

	// Wait for the client to exit.
	if err = sc.wait(childEnv, cmd, clientErrCh); err != nil {
		return err
	}

	// Check if the storage node that ignored applies has synced.
	sc.logger.Info("checking if roots have been synced")

	storageNode := sc.basicImpl.net.StorageWorkers()[2]
	args := []string{
		"debug", "storage", "check-roots",
		"--log.level", "debug",
		"--debug.dont_blame_oasis",
		"--storage.debug.client.address", "unix:" + storageNode.SocketPath(),
		"--address", "unix:" + storageNode.SocketPath(),
		sc.basicImpl.net.Runtimes()[1].ID().String(),
	}
	if err = runSubCommand(childEnv, "storage-check-roots", sc.basicImpl.net.Config().NodeBinary, args); err != nil {
		return errors.Wrap(err, "scenario/e2e/storage_sync: root check failed after sync")
	}

	return nil
}
