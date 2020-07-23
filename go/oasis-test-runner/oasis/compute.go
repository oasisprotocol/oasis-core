package oasis

import (
	"fmt"

	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	storageClient "github.com/oasisprotocol/oasis-core/go/storage/client"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common"
)

const (
	computeIdentitySeedTemplate = "ekiden node worker %d"

	ByzantineDefaultIdentitySeed = "ekiden byzantine node worker" // slot 0
	ByzantineSlot1IdentitySeed   = "ekiden byzantine node worker, luck=1"
	ByzantineSlot2IdentitySeed   = "ekiden byzantine node worker, luck=11"
	ByzantineSlot3IdentitySeed   = "ekiden byzantine node worker, luck=6"
)

// Compute is an Oasis compute node.
type Compute struct { // nolint: maligned
	Node

	entity *Entity

	runtimeProvisioner string

	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16

	runtimes []int
}

// ComputeCfg is the Oasis compute node configuration.
type ComputeCfg struct {
	NodeCfg

	Entity *Entity

	RuntimeProvisioner string

	Runtimes []int
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

// Exports path returns the path to the node's exports data dir.
func (worker *Compute) ExportsPath() string {
	return nodeExportsPath(worker.dir)
}

// Start starts an Oasis node.
func (worker *Compute) Start() error {
	return worker.startNode()
}

func (worker *Compute) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		workerCertificateRotation(true).
		tendermintCoreListenAddress(worker.consensusPort).
		tendermintSubmissionGasPrice(worker.consensus.SubmissionGasPrice).
		tendermintPrune(worker.consensus.PruneNumKept).
		storageBackend(storageClient.BackendName).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerComputeEnabled().
		workerRuntimeProvisioner(worker.runtimeProvisioner).
		workerRuntimeSGXLoader(worker.net.cfg.RuntimeSGXLoaderBinary).
		workerTxnschedulerCheckTxEnabled().
		appendNetwork(worker.net).
		appendSeedNodes(worker.net).
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
		// XXX: could support configurable binary idx if ever needed.
		args = args.appendComputeNodeRuntime(v, 0)
	}

	if err := worker.net.startOasisNode(&worker.Node, nil, args); err != nil {
		return fmt.Errorf("oasis/compute: failed to launch node %s: %w", worker.Name, err)
	}

	return nil
}

// NewCompute provisions a new compute node and adds it to the network.
func (net *Network) NewCompute(cfg *ComputeCfg) (*Compute, error) {
	computeName := fmt.Sprintf("compute-%d", len(net.computeWorkers))

	computeDir, err := net.baseDir.NewSubDir(computeName)
	if err != nil {
		net.logger.Error("failed to create compute subdir",
			"err", err,
			"compute_name", computeName,
		)
		return nil, fmt.Errorf("oasis/compute: failed to create compute subdir: %w", err)
	}

	// Pre-provision the node identity so that we can update the entity.
	seed := fmt.Sprintf(computeIdentitySeedTemplate, len(net.computeWorkers))
	nodeKey, _, _, err := net.provisionNodeIdentity(computeDir, seed, false)
	if err != nil {
		return nil, fmt.Errorf("oasis/compute: failed to provision node identity: %w", err)
	}
	if err := cfg.Entity.addNode(nodeKey); err != nil {
		return nil, err
	}

	if cfg.RuntimeProvisioner == "" {
		cfg.RuntimeProvisioner = commonWorker.RuntimeProvisionerSandboxed
	}

	worker := &Compute{
		Node: Node{
			Name:                                     computeName,
			net:                                      net,
			dir:                                      computeDir,
			termEarlyOk:                              cfg.AllowEarlyTermination,
			termErrorOk:                              cfg.AllowErrorTermination,
			disableDefaultLogWatcherHandlerFactories: cfg.DisableDefaultLogWatcherHandlerFactories,
			logWatcherHandlerFactories:               cfg.LogWatcherHandlerFactories,
			consensus:                                cfg.Consensus,
			noAutoStart:                              cfg.NoAutoStart,
		},
		entity:             cfg.Entity,
		runtimeProvisioner: cfg.RuntimeProvisioner,
		consensusPort:      net.nextNodePort,
		clientPort:         net.nextNodePort + 1,
		p2pPort:            net.nextNodePort + 2,
		runtimes:           cfg.Runtimes,
	}
	worker.doStartNode = worker.startNode
	copy(worker.NodeID[:], nodeKey[:])

	net.computeWorkers = append(net.computeWorkers, worker)
	net.nextNodePort += 3

	if err := net.AddLogWatcher(&worker.Node); err != nil {
		net.logger.Error("failed to add log watcher",
			"err", err,
			"compute_name", computeName,
		)
		return nil, fmt.Errorf("oasis/compute: failed to add log watcher for %s: %w", computeName, err)
	}

	return worker, nil
}
