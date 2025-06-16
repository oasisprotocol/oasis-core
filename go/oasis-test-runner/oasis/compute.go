package oasis

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	workerStorage "github.com/oasisprotocol/oasis-core/go/worker/storage/api"
)

const (
	computeIdentitySeedTemplate = "ekiden node worker %d"

	// ByzantineDefaultIdentitySeed for slot 3.
	ByzantineDefaultIdentitySeed = "ekiden byzantine node worker, luck=6"
	ByzantineSlot1IdentitySeed   = "ekiden byzantine node worker, luck=1"
)

// Compute is an Oasis compute node.
type Compute struct { // nolint: maligned
	sync.RWMutex

	*Node

	consensusPort uint16
	p2pPort       uint16

	runtimes           []int
	runtimeConfig      map[int]map[string]any
	runtimeProvisioner runtimeConfig.RuntimeProvisioner

	sentryIndices []int
	sentryPubKey  signature.PublicKey

	storageBackend            string
	disablePublicRPC          bool
	checkpointSyncDisabled    bool
	checkpointCheckInterval   time.Duration
	checkpointParallelChunker bool
}

// ComputeCfg is the Oasis compute node configuration.
type ComputeCfg struct {
	NodeCfg

	Runtimes           []int
	RuntimeConfig      map[int]map[string]any
	RuntimeProvisioner runtimeConfig.RuntimeProvisioner
	RuntimeStatePaths  map[int]string

	SentryIndices []int

	StorageBackend            string
	DisablePublicRPC          bool
	CheckpointSyncDisabled    bool
	CheckpointCheckInterval   time.Duration
	CheckpointParallelChunker bool
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

	args.configureDebugCrashPoints(worker.crashPointsProbability).
		appendNetwork(worker.net)

	if worker.entity.isDebugTestEntity {
		args.appendDebugTestEntity()
	}

	for _, idx := range worker.runtimes {
		v := worker.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		worker.addHostedRuntime(v, worker.runtimeConfig[idx])
	}

	return nil
}

func (worker *Compute) ModifyConfig() error {
	worker.RLock()
	defer worker.RUnlock()

	worker.Config.Consensus.ListenAddress = allInterfacesAddr + ":" + strconv.Itoa(int(worker.consensusPort))
	worker.Config.Consensus.ExternalAddress = localhostAddr + ":" + strconv.Itoa(int(worker.consensusPort))

	if worker.supplementarySanityInterval > 0 {
		worker.Config.Consensus.SupplementarySanity.Enabled = true
		worker.Config.Consensus.SupplementarySanity.Interval = worker.supplementarySanityInterval
	}

	worker.Config.P2P.Port = worker.p2pPort

	if !worker.entity.isDebugTestEntity {
		entityID, _ := worker.entity.ID().MarshalText() // Cannot fail.
		worker.Config.Registration.EntityID = string(entityID)
	}

	worker.Config.Mode = config.ModeCompute
	worker.Config.Runtime.Provisioner = worker.runtimeProvisioner
	worker.Config.Runtime.SGX.Loader = worker.net.cfg.RuntimeSGXLoaderBinary
	worker.Config.Runtime.AttestInterval = worker.net.cfg.RuntimeAttestInterval

	worker.Config.Storage.Backend = worker.storageBackend
	worker.Config.Storage.PublicRPCEnabled = !worker.disablePublicRPC
	worker.Config.Storage.CheckpointSyncDisabled = worker.checkpointSyncDisabled
	worker.Config.Storage.Checkpointer.Enabled = true
	worker.Config.Storage.Checkpointer.CheckInterval = worker.checkpointCheckInterval
	worker.Config.Storage.Checkpointer.ParallelChunker = worker.checkpointParallelChunker

	// Sentry configuration.
	sentries, err := resolveSentries(worker.net, worker.sentryIndices)
	if err != nil {
		return err
	}

	if len(sentries) > 0 {
		worker.Config.Consensus.P2P.DisablePeerExchange = true
		worker.AddSentriesToConfig(sentries)
	} else {
		worker.AddSeedNodesToConfig()
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
	err = host.setProvisionedIdentity(fmt.Sprintf(computeIdentitySeedTemplate, len(net.computeWorkers)))
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
		cfg.RuntimeProvisioner = runtimeConfig.RuntimeProvisionerSandboxed
	}
	if cfg.StorageBackend == "" {
		cfg.StorageBackend = defaultStorageBackend
	}
	// Initialize runtime state paths.
	for i, path := range cfg.RuntimeStatePaths {
		stateDir := runtimeConfig.GetRuntimeStateDir(host.DataDir(), net.Runtimes()[i].descriptor.ID)
		net.logger.Info("copying runtime state", "from", path, "to", stateDir)
		if err := common.CopyDir(path, stateDir); err != nil {
			return nil, fmt.Errorf("oasis/compute: failed to copy runtime state: %w", err)
		}
		net.logger.Info("state copied", "from", path, "to", stateDir)
	}

	worker := &Compute{
		Node:                      host,
		storageBackend:            cfg.StorageBackend,
		sentryIndices:             cfg.SentryIndices,
		disablePublicRPC:          cfg.DisablePublicRPC,
		checkpointSyncDisabled:    cfg.CheckpointSyncDisabled,
		checkpointCheckInterval:   cfg.CheckpointCheckInterval,
		checkpointParallelChunker: cfg.CheckpointParallelChunker,
		sentryPubKey:              sentryPubKey,
		runtimeProvisioner:        cfg.RuntimeProvisioner,
		consensusPort:             host.getProvisionedPort(nodePortConsensus),
		p2pPort:                   host.getProvisionedPort(nodePortP2P),
		runtimes:                  cfg.Runtimes,
		runtimeConfig:             cfg.RuntimeConfig,
	}

	// Remove any exploded bundles on cleanup.
	net.env.AddOnCleanup(func() {
		_ = os.RemoveAll(bundle.ExplodedPath(worker.dir.String()))
	})

	net.computeWorkers = append(net.computeWorkers, worker)
	host.features = append(host.features, worker)

	return worker, nil
}
