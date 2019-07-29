package ekiden

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

// Storage is an ekiden storage node.
type Storage struct {
	net *Network
	dir *env.Dir

	backend string
	entity  *Entity

	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16
}

// StorageCfg is the ekiden storage node configuration.
type StorageCfg struct {
	Backend string
	Entity  *Entity
}

// LogPath returns the path to the node's log.
func (worker *Storage) LogPath() string {
	return nodeLogPath(worker.dir)
}

func (worker *Storage) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(worker.consensusPort).
		roothashTendermintIndexBlocks().
		storageBackend(worker.backend).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerStorageEnabled().
		appendNetwork(worker.net).
		appendEntity(worker.entity)
	for _, v := range worker.net.runtimes {
		args = args.workerRuntimeID(v.id)
	}

	if err := worker.net.startEkidenNode(worker.dir, args, "storage"); err != nil {
		return errors.Wrap(err, "ekiden/storage: failed to launch node")
	}

	return nil
}

// NewStorage provisions a new storage node and adds it to the network.
func (net *Network) NewStorage(cfg *StorageCfg) (*Storage, error) {
	storageName := fmt.Sprintf("storage-%d", len(net.storageWorkers))

	storageDir, err := net.baseDir.NewSubDir(storageName)
	if err != nil {
		net.logger.Error("failed to create storage subdir",
			"err", err,
			"storage_name", storageName,
		)
		return nil, errors.Wrap(err, "ekiden/storage: failed to create storage subdir")
	}

	worker := &Storage{
		net:           net,
		dir:           storageDir,
		backend:       cfg.Backend,
		entity:        cfg.Entity,
		consensusPort: net.nextNodePort,
		clientPort:    net.nextNodePort + 1,
		p2pPort:       net.nextNodePort + 2,
	}

	net.storageWorkers = append(net.storageWorkers, worker)
	net.nextNodePort += 3

	return worker, nil
}
