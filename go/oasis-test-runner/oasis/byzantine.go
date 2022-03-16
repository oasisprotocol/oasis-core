package oasis

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// Byzantine is an Oasis byzantine node.
type Byzantine struct {
	*Node

	script    string
	extraArgs []Argument

	runtime         int
	consensusPort   uint16
	p2pPort         uint16
	activationEpoch beacon.EpochTime
}

// ByzantineCfg is the Oasis byzantine node configuration.
type ByzantineCfg struct {
	NodeCfg

	Script    string
	ExtraArgs []Argument

	ForceElectParams *scheduler.ForceElectCommitteeRole

	IdentitySeed string

	ActivationEpoch beacon.EpochTime
	Runtime         int
}

func (worker *Byzantine) AddArgs(args *argBuilder) error {
	args.debugDontBlameOasis().
		debugAllowRoot().
		debugAllowTestKeys().
		debugSetRlimit().
		debugEnableProfiling(worker.Node.pprofPort).
		tendermintDebugAllowDuplicateIP().
		tendermintCoreAddress(worker.consensusPort).
		tendermintDebugAddrBookLenient().
		tendermintSubmissionGasPrice(worker.consensus.SubmissionGasPrice).
		workerP2pPort(worker.p2pPort).
		appendSeedNodes(worker.net.seeds).
		appendEntity(worker.entity).
		byzantineActivationEpoch(worker.activationEpoch)

	if worker.runtime > 0 {
		args.byzantineRuntimeID(worker.net.runtimes[worker.runtime].ID())
	}
	for _, v := range worker.net.Runtimes() {
		if v.kind == registry.KindCompute && v.teeHardware == node.TEEHardwareIntelSGX {
			args.byzantineFakeSGX()
			args.byzantineVersionFakeEnclaveID(v)
		}
	}
	args.vec = append(args.vec, worker.extraArgs...)

	return nil
}

func (worker *Byzantine) CustomStart(args *argBuilder) error {
	if err := worker.net.startOasisNode(worker.Node, []string{"debug", "byzantine", worker.script}, args); err != nil {
		return fmt.Errorf("oasis/byzantine: failed to launch node %s: %w", worker.Name, err)
	}

	return nil
}

// NewByzantine provisions a new byzantine node and adds it to the network.
func (net *Network) NewByzantine(cfg *ByzantineCfg) (*Byzantine, error) {
	byzantineName := fmt.Sprintf("byzantine-%d", len(net.byzantine))
	host, err := net.GetNamedNode(byzantineName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	if cfg.Script == "" {
		return nil, fmt.Errorf("oasis/byzantine: empty script name: %w", err)
	}

	// Generate a deterministic identity as the Byzantine node scripts usually
	// require specific roles in the first round.
	if cfg.IdentitySeed == "" {
		return nil, fmt.Errorf("oasis/byzantine: empty identity seed")
	}

	// Pre-provision the node identity so that we can update the entity.
	host.nodeSigner, host.p2pSigner, host.sentryCert, err = net.provisionNodeIdentity(host.dir, cfg.IdentitySeed, false)
	if err != nil {
		return nil, fmt.Errorf("oasis/byzantine: failed to provision node identity: %w", err)
	}
	if err := cfg.Entity.addNode(host.nodeSigner); err != nil {
		return nil, err
	}

	worker := &Byzantine{
		Node:            host,
		script:          cfg.Script,
		extraArgs:       cfg.ExtraArgs,
		consensusPort:   host.getProvisionedPort(nodePortConsensus),
		p2pPort:         host.getProvisionedPort(nodePortP2P),
		activationEpoch: cfg.ActivationEpoch,
		runtime:         cfg.Runtime,
	}
	copy(worker.NodeID[:], host.nodeSigner[:])

	net.byzantine = append(net.byzantine, worker)
	host.features = append(host.features, worker)

	if cfg.Runtime >= 0 {
		rt := net.runtimes[cfg.Runtime].ID()
		pk := host.nodeSigner

		if net.cfg.SchedulerForceElect == nil {
			net.cfg.SchedulerForceElect = make(map[common.Namespace]map[signature.PublicKey]*scheduler.ForceElectCommitteeRole)
		}
		if net.cfg.SchedulerForceElect[rt] == nil {
			net.cfg.SchedulerForceElect[rt] = make(map[signature.PublicKey]*scheduler.ForceElectCommitteeRole)
		}
		if params := cfg.ForceElectParams; params != nil {
			tmpParams := *params
			net.cfg.SchedulerForceElect[rt][pk] = &tmpParams
		}
	}

	return worker, nil
}
