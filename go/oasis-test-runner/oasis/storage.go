package oasis

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
)

const storageIdentitySeedTemplate = "ekiden node storage %d"

// Storage is an Oasis storage node.
type Storage struct { // nolint: maligned
	*Node

	sentryIndices []int

	backend string

	disableCertRotation     bool
	disablePublicRPC        bool
	ignoreApplies           bool
	checkpointSyncDisabled  bool
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

	DisableCertRotation     bool
	DisablePublicRPC        bool
	IgnoreApplies           bool
	CheckpointSyncDisabled  bool
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

// WaitForRoot waits until the node syncs up to the given root.
func (worker *Storage) WaitForRound(ctx context.Context, runtimeID common.Namespace, round uint64) (uint64, error) {
	ctrl, err := NewController(worker.SocketPath())
	if err != nil {
		return 0, err
	}
	req := &workerStorage.WaitForRoundRequest{
		RuntimeID: runtimeID,
		Round:     round,
	}
	resp, err := ctrl.StorageWorker.WaitForRound(ctx, req)
	if err != nil {
		return 0, err
	}
	return resp.LastRound, nil
}

// PauseCheckpointer pauses or unpauses the storage worker's checkpointer.
func (worker *Storage) PauseCheckpointer(ctx context.Context, runtimeID common.Namespace, pause bool) error {
	ctrl, err := NewController(worker.SocketPath())
	if err != nil {
		return err
	}
	req := &workerStorage.PauseCheckpointerRequest{
		RuntimeID: runtimeID,
		Pause:     pause,
	}
	return ctrl.StorageWorker.PauseCheckpointer(ctx, req)
}

func (worker *Storage) AddArgs(args *argBuilder) error {
	args.debugDontBlameOasis().
		debugAllowTestKeys().
		debugSetRlimit().
		debugEnableProfiling(worker.Node.pprofPort).
		workerCertificateRotation(!worker.disableCertRotation).
		tendermintCoreAddress(worker.consensusPort).
		tendermintSubmissionGasPrice(worker.consensus.SubmissionGasPrice).
		tendermintPrune(worker.consensus.PruneNumKept).
		tendermintRecoverCorruptedWAL(worker.consensus.TendermintRecoverCorruptedWAL).
		storageBackend(worker.backend).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerStorageEnabled().
		workerStoragePublicRPCEnabled(!worker.disablePublicRPC).
		workerStorageDebugIgnoreApplies(worker.ignoreApplies).
		workerStorageDebugDisableCheckpointSync(worker.checkpointSyncDisabled).
		workerStorageCheckpointCheckInterval(worker.checkpointCheckInterval).
		configureDebugCrashPoints(worker.crashPointsProbability).
		tendermintSupplementarySanity(worker.supplementarySanityInterval).
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
		args.runtimeSupported(v.id)
	}

	// Sentry configuration.
	sentries, err := resolveSentries(worker.net, worker.sentryIndices)
	if err != nil {
		return err
	}

	if len(sentries) > 0 {
		args.addSentries(sentries).
			tendermintDisablePeerExchange()
	} else {
		args.appendSeedNodes(worker.net.seeds)
	}

	return nil
}

// NewStorage provisions a new storage node and adds it to the network.
func (net *Network) NewStorage(cfg *StorageCfg) (*Storage, error) {
	storageName := fmt.Sprintf("storage-%d", len(net.storageWorkers))
	host, err := net.GetNamedNode(storageName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	// Pre-provision the node identity so that we can update the entity.
	err = host.setProvisionedIdentity(cfg.DisableCertRotation, fmt.Sprintf(storageIdentitySeedTemplate, len(net.storageWorkers)))
	if err != nil {
		return nil, fmt.Errorf("oasis/storage: failed to provision node identity: %w", err)
	}
	// Sentry client cert.
	pk, ok := host.sentryCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oasis/storage: bad sentry client public key type (expected: Ed25519 got: %T)", host.sentryCert.PublicKey)
	}
	var sentryPubKey signature.PublicKey
	if err := sentryPubKey.UnmarshalBinary(pk[:]); err != nil {
		return nil, fmt.Errorf("oasis/storage: sentry client public key unmarshal failure: %w", err)
	}

	worker := &Storage{
		Node:                    host,
		backend:                 cfg.Backend,
		sentryIndices:           cfg.SentryIndices,
		disableCertRotation:     cfg.DisableCertRotation,
		disablePublicRPC:        cfg.DisablePublicRPC,
		ignoreApplies:           cfg.IgnoreApplies,
		checkpointSyncDisabled:  cfg.CheckpointSyncDisabled,
		checkpointCheckInterval: cfg.CheckpointCheckInterval,
		sentryPubKey:            sentryPubKey,
		tmAddress:               crypto.PublicKeyToTendermint(&host.p2pSigner).Address().String(),
		consensusPort:           host.getProvisionedPort(nodePortConsensus),
		clientPort:              host.getProvisionedPort(nodePortClient),
		p2pPort:                 host.getProvisionedPort(nodePortP2P),
		runtimes:                cfg.Runtimes,
	}

	net.storageWorkers = append(net.storageWorkers, worker)
	host.features = append(host.features, worker)

	return worker, nil
}
