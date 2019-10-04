package ekiden

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/storage/database"
)

// Storage is an ekiden storage node.
type Storage struct {
	net *Network
	dir *env.Dir

	backend       string
	entity        *Entity
	ignoreApplies bool

	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16
}

// StorageCfg is the ekiden storage node configuration.
type StorageCfg struct {
	Backend       string
	Entity        *Entity
	IgnoreApplies bool
}

// SocketPath returns the path to the storage node's gRPC socket.
func (worker *Storage) SocketPath() string {
	return internalSocketPath(worker.dir)
}

// LogPath returns the path to the node's log.
func (worker *Storage) LogPath() string {
	return nodeLogPath(worker.dir)
}

// IdentityKeyPath returns the path to the node's identity key.
func (worker *Storage) IdentityKeyPath() string {
	return nodeIdentityKeyPath(worker.dir)
}

// P2PKeyPath returns the path to the node's P2P key.
func (worker *Storage) P2PKeyPath() string {
	return nodeP2PKeyPath(worker.dir)
}

// TLSKeyPath returns the path to the node's TLS key.
func (worker *Storage) TLSKeyPath() string {
	return nodeTLSKeyPath(worker.dir)
}

// TLSCertPath returns the path to the node's TLS certificate.
func (worker *Storage) TLSCertPath() string {
	return nodeTLSCertPath(worker.dir)
}

// DatabasePath returns the path to the node's database.
func (worker *Storage) DatabasePath() string {
	return filepath.Join(worker.dir.String(), database.DefaultFileName(worker.backend))
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
		workerStorageDebugIgnoreApplies(worker.ignoreApplies).
		appendNetwork(worker.net).
		appendEntity(worker.entity)
	for _, v := range worker.net.runtimes {
		if v.kind != registry.KindCompute {
			continue
		}
		args = args.workerRuntimeID(v.id)
	}

	if _, err := worker.net.startEkidenNode(worker.dir, nil, args, "storage", false, false); err != nil {
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
		ignoreApplies: cfg.IgnoreApplies,
		consensusPort: net.nextNodePort,
		clientPort:    net.nextNodePort + 1,
		p2pPort:       net.nextNodePort + 2,
	}

	net.storageWorkers = append(net.storageWorkers, worker)
	net.nextNodePort += 3

	return worker, nil
}
