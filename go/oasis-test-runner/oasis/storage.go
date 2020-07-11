package oasis

import (
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
)

const storageIdentitySeedTemplate = "ekiden node storage %d"

// Storage is an Oasis storage node.
type Storage struct { // nolint: maligned
	Node

	sentryIndices []int

	backend string
	entity  *Entity

	disableCertRotation     bool
	ignoreApplies           bool
	checkpointCheckInterval time.Duration

	sentryPubKey  signature.PublicKey
	tmAddress     string
	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16

	runtimes []int
}

// StorageCfg is the Oasis storage node configuration.
type StorageCfg struct { // nolint: maligned
	NodeCfg

	SentryIndices []int
	Backend       string
	Entity        *Entity

	DisableCertRotation     bool
	IgnoreApplies           bool
	CheckpointCheckInterval time.Duration

	Runtimes []int
}

// IdentityKeyPath returns the path to the node's identity key.
func (worker *Storage) IdentityKeyPath() string {
	return nodeIdentityKeyPath(worker.dir)
}

// GetClientAddress returns the storage node endpoint address.
func (worker *Storage) GetClientAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", worker.clientPort)
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
		workerCertificateRotation(!worker.disableCertRotation).
		tendermintCoreListenAddress(worker.consensusPort).
		tendermintSubmissionGasPrice(worker.consensus.SubmissionGasPrice).
		tendermintPrune(worker.consensus.PruneNumKept).
		storageBackend(worker.backend).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerStorageEnabled().
		workerStorageDebugIgnoreApplies(worker.ignoreApplies).
		workerStorageCheckpointCheckInterval(worker.checkpointCheckInterval).
		appendNetwork(worker.net).
		appendEntity(worker.entity)
	var runtimeArray []*Runtime
	if len(worker.runtimes) > 0 {
		for _, idx := range worker.runtimes {
			runtimeArray = append(runtimeArray, worker.net.runtimes[idx])
		}
	} else {
		runtimeArray = worker.net.runtimes
	}
	for _, v := range runtimeArray {
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
		return nil, fmt.Errorf("oasis/storage: failed to create storage subdir: %w", err)
	}

	// Pre-provision the node identity so that we can update the entity.
	seed := fmt.Sprintf(storageIdentitySeedTemplate, len(net.storageWorkers))
	nodeKey, p2pKey, sentryClientCert, err := net.provisionNodeIdentity(storageDir, seed, cfg.DisableCertRotation)
	if err != nil {
		return nil, fmt.Errorf("oasis/storage: failed to provision node identity: %w", err)
	}
	if err := cfg.Entity.addNode(nodeKey); err != nil {
		return nil, err
	}
	// Sentry client cert.
	pk, ok := sentryClientCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oasis/storage: bad sentry client public key type (expected: Ed25519 got: %T)", sentryClientCert.PublicKey)
	}
	var sentryPubKey signature.PublicKey
	if err := sentryPubKey.UnmarshalBinary(pk[:]); err != nil {
		return nil, fmt.Errorf("oasis/storage: sentry client public key unmarshal failure: %w", err)
	}

	worker := &Storage{
		Node: Node{
			Name:                                     storageName,
			net:                                      net,
			dir:                                      storageDir,
			disableDefaultLogWatcherHandlerFactories: cfg.DisableDefaultLogWatcherHandlerFactories,
			logWatcherHandlerFactories:               cfg.LogWatcherHandlerFactories,
			consensus:                                cfg.Consensus,
		},
		backend:                 cfg.Backend,
		entity:                  cfg.Entity,
		sentryIndices:           cfg.SentryIndices,
		disableCertRotation:     cfg.DisableCertRotation,
		ignoreApplies:           cfg.IgnoreApplies,
		checkpointCheckInterval: cfg.CheckpointCheckInterval,
		sentryPubKey:            sentryPubKey,
		tmAddress:               crypto.PublicKeyToTendermint(&p2pKey).Address().String(),
		consensusPort:           net.nextNodePort,
		clientPort:              net.nextNodePort + 1,
		p2pPort:                 net.nextNodePort + 2,
		runtimes:                cfg.Runtimes,
	}
	worker.doStartNode = worker.startNode
	copy(worker.NodeID[:], nodeKey[:])

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
