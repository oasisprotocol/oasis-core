package oasis

import (
	"fmt"
	"sync"

	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
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

	Runtimes      []int
	RuntimeConfig map[int]map[string]interface{}
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

func (worker *Compute) AddArgs(args *argBuilder) error {
	worker.RLock()
	defer worker.RUnlock()

	args.debugDontBlameOasis().
		debugAllowTestKeys().
		debugEnableProfiling(worker.Node.pprofPort).
		workerCertificateRotation(true).
		tendermintCoreAddress(worker.consensusPort).
		tendermintSubmissionGasPrice(worker.consensus.SubmissionGasPrice).
		tendermintPrune(worker.consensus.PruneNumKept).
		tendermintRecoverCorruptedWAL(worker.consensus.TendermintRecoverCorruptedWAL).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerComputeEnabled().
		runtimeProvisioner(worker.runtimeProvisioner).
		runtimeSGXLoader(worker.net.cfg.RuntimeSGXLoaderBinary).
		configureDebugCrashPoints(worker.crashPointsProbability).
		tendermintSupplementarySanity(worker.supplementarySanityInterval).
		appendNetwork(worker.net).
		appendSeedNodes(worker.net.seeds).
		appendEntity(worker.entity)

	for _, idx := range worker.runtimes {
		v := worker.net.runtimes[idx]
		// XXX: could support configurable binary idx if ever needed.
		worker.addHostedRuntime(v, v.teeHardware, 0, worker.runtimeConfig[idx])
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
	err = host.setProvisionedIdentity(false, fmt.Sprintf(computeIdentitySeedTemplate, len(net.computeWorkers)))
	if err != nil {
		return nil, fmt.Errorf("oasis/compute: failed to provision node identity: %w", err)
	}

	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = runtimeRegistry.RuntimeProvisionerSandboxed
	}

	worker := &Compute{
		Node:               host,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		consensusPort:      host.getProvisionedPort(nodePortConsensus),
		clientPort:         host.getProvisionedPort(nodePortClient),
		p2pPort:            host.getProvisionedPort(nodePortP2P),
		runtimes:           cfg.Runtimes,
		runtimeConfig:      cfg.RuntimeConfig,
	}

	net.computeWorkers = append(net.computeWorkers, worker)
	host.features = append(host.features, worker)

	return worker, nil
}
