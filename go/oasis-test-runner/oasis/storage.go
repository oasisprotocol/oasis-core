package oasis

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/storage/database"
)

const storageIdentitySeedTemplate = "ekiden node storage %d"

// Storage is an Oasis storage node.
type Storage struct { // nolint: maligned
	Node

	sentryIndices []int

	backend string
	entity  *Entity

	ignoreApplies           bool
	checkpointCheckInterval time.Duration

	tmAddress     string
	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16
}

// StorageCfg is the Oasis storage node configuration.
type StorageCfg struct { // nolint: maligned
	NodeCfg

	SentryIndices []int
	Backend       string
	Entity        *Entity

	IgnoreApplies           bool
	CheckpointCheckInterval time.Duration
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
	var err error

	sentries, err := resolveSentries(worker.net, worker.sentryIndices)
	if err != nil {
		return err
	}

	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		tendermintCoreListenAddress(worker.consensusPort).
		tendermintSubmissionGasPrice(worker.submissionGasPrice).
		storageBackend(worker.backend).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerStorageEnabled().
		workerStorageDebugIgnoreApplies(worker.ignoreApplies).
		workerStorageCheckpointCheckInterval(worker.checkpointCheckInterval).
		appendNetwork(worker.net).
		appendSeedNodes(worker.net).
		appendEntity(worker.entity)
	for _, v := range worker.net.runtimes {
		if v.kind != registry.KindCompute {
			continue
		}
		args = args.runtimeSupported(v.id)
	}

	// Sentry configuration.
	if len(sentries) > 0 {
		args = args.addSentries(sentries).
			tendermintDisablePeerExchange()
	} else {
		args = args.appendSeedNodes(worker.net)
	}

	if err = worker.net.startOasisNode(&worker.Node, nil, args); err != nil {
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
	seed := fmt.Sprintf(storageIdentitySeedTemplate, len(net.storageWorkers))
	publicKey, err := net.provisionNodeIdentity(storageDir, seed)
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
			submissionGasPrice:                       cfg.SubmissionGasPrice,
		},
		backend:                 cfg.Backend,
		entity:                  cfg.Entity,
		sentryIndices:           cfg.SentryIndices,
		ignoreApplies:           cfg.IgnoreApplies,
		checkpointCheckInterval: cfg.CheckpointCheckInterval,
		tmAddress:               crypto.PublicKeyToTendermint(&publicKey).Address().String(),
		consensusPort:           net.nextNodePort,
		clientPort:              net.nextNodePort + 1,
		p2pPort:                 net.nextNodePort + 2,
	}
	worker.doStartNode = worker.startNode
	copy(worker.NodeID[:], publicKey[:])

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
