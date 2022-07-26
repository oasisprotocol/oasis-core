package oasis

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	"github.com/oasisprotocol/oasis-core/go/runtime/registry"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
)

const (
	computeIdentitySeedTemplate = "ekiden node worker %d"

	ByzantineDefaultIdentitySeed = "ekiden byzantine node worker, luck=6" // Slot 3.
	ByzantineSlot1IdentitySeed   = "ekiden byzantine node worker, luck=1"
)

// Compute is an Oasis compute node.
type Compute struct { // nolint: maligned
	sync.RWMutex

	*Node

	runtimeProvisioner string

	sentryIndices []int

	storageBackend          string
	disableCertRotation     bool
	disablePublicRPC        bool
	checkpointSyncDisabled  bool
	checkpointCheckInterval time.Duration

	sentryPubKey  signature.PublicKey
	tmAddress     string
	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16

	runtimes      []int
	runtimeConfig map[int]map[string]interface{}
}

// ComputeCfg is the Oasis compute node configuration.
type ComputeCfg struct {
	NodeCfg

	RuntimeProvisioner string

	Runtimes          []int
	RuntimeConfig     map[int]map[string]interface{}
	RuntimeStatePaths map[int]string

	SentryIndices []int

	StorageBackend          string
	DisableCertRotation     bool
	DisablePublicRPC        bool
	CheckpointSyncDisabled  bool
	CheckpointCheckInterval time.Duration
}

// UpdateRuntimes updates the worker node runtimes.
func (worker *Compute) UpdateRuntimes(runtimes []int) {
	worker.Lock()
	defer worker.Unlock()
	worker.runtimes = runtimes
}

// IdentityKeyPath returns the path to the node's identity key.
func (worker *Compute) IdentityKeyPath() string {
	return nodeIdentityKeyPath(worker.dir)
}

// P2PKeyPath returns the path to the node's P2P key.
func (worker *Compute) P2PKeyPath() string {
	return nodeP2PKeyPath(worker.dir)
}

// ConsensusKeyPath returns the path to the node's consensus key.
func (worker *Compute) ConsensusKeyPath() string {
	return nodeConsensusKeyPath(worker.dir)
}

// TLSKeyPath returns the path to the node's TLS key.
func (worker *Compute) TLSKeyPath() string {
	return nodeTLSKeyPath(worker.dir)
}

// TLSCertPath returns the path to the node's TLS certificate.
func (worker *Compute) TLSCertPath() string {
	return nodeTLSCertPath(worker.dir)
}

// ExportsPath returns the path to the node's exports data dir.
func (worker *Compute) ExportsPath() string {
	return nodeExportsPath(worker.dir)
}

// DatabasePath returns the path to the node's database.
func (worker *Compute) DatabasePath() string {
	return filepath.Join(worker.dir.String(), database.DefaultFileName(worker.storageBackend))
}

// GetClientAddress returns the compute node endpoint address.
func (worker *Compute) GetClientAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", worker.clientPort)
}

// PauseCheckpointer pauses or unpauses the storage worker's checkpointer.
func (worker *Compute) PauseCheckpointer(ctx context.Context, runtimeID common.Namespace, pause bool) error {
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

func (worker *Compute) AddArgs(args *argBuilder) error {
	worker.RLock()
	defer worker.RUnlock()

	args.debugDontBlameOasis().
		debugAllowRoot().
		debugAllowTestKeys().
		debugSetRlimit().
		debugEnableProfiling(worker.Node.pprofPort).
		workerCertificateRotation(!worker.disableCertRotation).
		tendermintCoreAddress(worker.consensusPort).
		tendermintSubmissionGasPrice(worker.consensus.SubmissionGasPrice).
		tendermintPrune(worker.consensus.PruneNumKept, worker.consensus.PruneInterval).
		tendermintRecoverCorruptedWAL(worker.consensus.TendermintRecoverCorruptedWAL).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		runtimeMode(runtimeRegistry.RuntimeModeCompute).
		runtimeProvisioner(worker.runtimeProvisioner).
		runtimeSGXLoader(worker.net.cfg.RuntimeSGXLoaderBinary).
		storageBackend(worker.storageBackend).
		workerStoragePublicRPCEnabled(!worker.disablePublicRPC).
		workerStorageDebugDisableCheckpointSync(worker.checkpointSyncDisabled).
		workerStorageCheckpointerEnabled(true).
		workerStorageCheckpointCheckInterval(worker.checkpointCheckInterval).
		configureDebugCrashPoints(worker.crashPointsProbability).
		tendermintSupplementarySanity(worker.supplementarySanityInterval).
		appendNetwork(worker.net).
		appendEntity(worker.entity)

	for _, idx := range worker.runtimes {
		v := worker.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		worker.addHostedRuntime(v, worker.runtimeConfig[idx])
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

// NewCompute provisions a new compute node and adds it to the network.
func (net *Network) NewCompute(cfg *ComputeCfg) (*Compute, error) {
	computeName := fmt.Sprintf("compute-%d", len(net.computeWorkers))
	host, err := net.GetNamedNode(computeName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	// Pre-provision the node identity so that we can update the entity.
	err = host.setProvisionedIdentity(cfg.DisableCertRotation, fmt.Sprintf(computeIdentitySeedTemplate, len(net.computeWorkers)))
	if err != nil {
		return nil, fmt.Errorf("oasis/compute: failed to provision node identity: %w", err)
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

	// Setup defaults.
	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = runtimeRegistry.RuntimeProvisionerSandboxed
	}
	if isNoSandbox() {
		cfg.RuntimeProvisioner = runtimeRegistry.RuntimeProvisionerUnconfined
	}
	if cfg.StorageBackend == "" {
		cfg.StorageBackend = database.BackendNameBadgerDB
	}
	// Initialize runtime state paths.
	for i, path := range cfg.RuntimeStatePaths {
		stateDir := registry.GetRuntimeStateDir(host.DataDir(), net.Runtimes()[i].descriptor.ID)
		net.logger.Info("copying runtime state", "from", path, "to", stateDir)
		if err := common.CopyDir(path, stateDir); err != nil {
			return nil, fmt.Errorf("oasis/compute: failed to copy runtime state: %w", err)
		}
		net.logger.Info("state copied", "from", path, "to", stateDir)
	}

	worker := &Compute{
		Node:                    host,
		storageBackend:          cfg.StorageBackend,
		sentryIndices:           cfg.SentryIndices,
		disableCertRotation:     cfg.DisableCertRotation,
		disablePublicRPC:        cfg.DisablePublicRPC,
		checkpointSyncDisabled:  cfg.CheckpointSyncDisabled,
		checkpointCheckInterval: cfg.CheckpointCheckInterval,
		sentryPubKey:            sentryPubKey,
		tmAddress:               crypto.PublicKeyToTendermint(&host.p2pSigner).Address().String(),
		runtimeProvisioner:      cfg.RuntimeProvisioner,
		consensusPort:           host.getProvisionedPort(nodePortConsensus),
		clientPort:              host.getProvisionedPort(nodePortClient),
		p2pPort:                 host.getProvisionedPort(nodePortP2P),
		runtimes:                cfg.Runtimes,
		runtimeConfig:           cfg.RuntimeConfig,
	}

	// Remove any exploded bundles on cleanup.
	net.env.AddOnCleanup(func() {
		_ = os.RemoveAll(bundle.ExplodedPath(worker.dir.String()))
	})

	net.computeWorkers = append(net.computeWorkers, worker)
	host.features = append(host.features, worker)

	return worker, nil
}
