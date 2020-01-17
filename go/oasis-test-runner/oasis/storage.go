package oasis

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"

	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/storage/database"
)

// Storage is an Oasis storage node.
type Storage struct { // nolint: maligned
	Node

	backend       string
	entity        *Entity
	ignoreApplies bool

	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16
}

// StorageCfg is the Oasis storage node configuration.
type StorageCfg struct { // nolint: maligned
	NodeCfg

	Backend       string
	Entity        *Entity
	IgnoreApplies bool
}

// IdentityKeyPath returns the path to the node's identity key.
func (worker *Storage) IdentityKeyPath() string {
	return nodeIdentityKeyPath(worker.dir)
}

// P2PKeyPath returns the path to the node's P2P key.
func (worker *Storage) P2PKeyPath() string {
	return nodeP2PKeyPath(worker.dir)
}

// ConsensusKeyPath returns the path to the node's consensus key.
func (worker *Storage) ConsensusKeyPath() string {
	return nodeConsensusKeyPath(worker.dir)
}

// TLSKeyPath returns the path to the node's TLS key.
func (worker *Storage) TLSKeyPath() string {
	return nodeTLSKeyPath(worker.dir)
}

// TLSCertPath returns the path to the node's TLS certificate.
func (worker *Storage) TLSCertPath() string {
	return nodeTLSCertPath(worker.dir)
}

// Exports path returns the path to the node's exports data dir.
func (worker *Storage) ExportsPath() string {
	return nodeExportsPath(worker.dir)
}

// DatabasePath returns the path to the node's database.
func (worker *Storage) DatabasePath() string {
	return filepath.Join(worker.dir.String(), database.DefaultFileName(worker.backend))
}

// Start starts an Oasis node.
func (worker *Storage) Start() error {
	return worker.startNode()
}

func (worker *Storage) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		tendermintCoreListenAddress(worker.consensusPort).
		storageBackend(worker.backend).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerStorageEnabled().
		workerStorageDebugIgnoreApplies(worker.ignoreApplies).
		appendNetwork(worker.net).
		appendSeedNodes(worker.net).
		appendEntity(worker.entity)
	for _, v := range worker.net.runtimes {
		if v.kind != registry.KindCompute {
			continue
		}
		args = args.runtimeSupported(v.id)
	}

	var err error
	if worker.cmd, worker.exitCh, err = worker.net.startOasisNode(
		worker.dir,
		nil,
		args,
		worker.Name,
		false,
		false,
	); err != nil {
		return fmt.Errorf("oasis/storage: failed to launch node %s: %w", worker.Name, err)
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
		return nil, errors.Wrap(err, "oasis/storage: failed to create storage subdir")
	}

	// Pre-provision the node identity so that we can update the entity.
	publicKey, err := provisionNodeIdentity(storageDir)
	if err != nil {
		return nil, errors.Wrap(err, "oasis/storage: failed to provision node identity")
	}
	if err := cfg.Entity.addNode(publicKey); err != nil {
		return nil, err
	}

	worker := &Storage{
		Node: Node{
			Name:                                     storageName,
			net:                                      net,
			dir:                                      storageDir,
			disableDefaultLogWatcherHandlerFactories: cfg.DisableDefaultLogWatcherHandlerFactories,
			logWatcherHandlerFactories:               cfg.LogWatcherHandlerFactories,
		},
		backend:       cfg.Backend,
		entity:        cfg.Entity,
		ignoreApplies: cfg.IgnoreApplies,
		consensusPort: net.nextNodePort,
		clientPort:    net.nextNodePort + 1,
		p2pPort:       net.nextNodePort + 2,
	}
	worker.doStartNode = worker.startNode

	net.storageWorkers = append(net.storageWorkers, worker)
	net.nextNodePort += 3

	if err := net.AddLogWatcher(&worker.Node); err != nil {
		net.logger.Error("failed to add log watcher",
			"err", err,
			"storage_name", storageName,
		)
		return nil, fmt.Errorf("oasis/storage: failed to add log watcher for %s: %w", storageName, err)
	}

	return worker, nil
}
