package oasis

import (
	"fmt"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// Byzantine is an Oasis byzantine node.
type Byzantine struct {
	Node

	script    string
	extraArgs []string

	entity *Entity

	consensusPort   uint16
	p2pPort         uint16
	activationEpoch beacon.EpochTime
}

// ByzantineCfg is the Oasis byzantine node configuration.
type ByzantineCfg struct {
	NodeCfg

	Script    string
	ExtraArgs []string

	IdentitySeed string
	Entity       *Entity

	ActivationEpoch beacon.EpochTime
}

func (worker *Byzantine) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		tendermintDebugAllowDuplicateIP().
		tendermintCoreAddress(worker.consensusPort).
		tendermintDebugAddrBookLenient().
		tendermintSubmissionGasPrice(worker.consensus.SubmissionGasPrice).
		workerP2pPort(worker.p2pPort).
		appendSeedNodes(worker.net.seeds).
		appendEntity(worker.entity).
		byzantineActivationEpoch(worker.activationEpoch)

	for _, v := range worker.net.Runtimes() {
		if v.kind == registry.KindCompute && v.teeHardware == node.TEEHardwareIntelSGX {
			args = args.byzantineFakeSGX()
			args = args.byzantineVersionFakeEnclaveID(v)
		}
	}
	args.vec = append(args.vec, worker.extraArgs...)

	if err := worker.net.startOasisNode(&worker.Node, []string{"debug", "byzantine", worker.script}, args); err != nil {
		return fmt.Errorf("oasis/byzantine: failed to launch node %s: %w", worker.Name, err)
	}

	return nil
}

// NewByzantine provisions a new byzantine node and adds it to the network.
func (net *Network) NewByzantine(cfg *ByzantineCfg) (*Byzantine, error) {
	byzantineName := fmt.Sprintf("byzantine-%d", len(net.byzantine))

	byzantineDir, err := net.baseDir.NewSubDir(byzantineName)
	if err != nil {
		net.logger.Error("failed to create byzantine node subdir",
			"err", err,
			"byzantine_name", byzantineName,
		)
		return nil, fmt.Errorf("oasis/byzantine: failed to create byzantine node subdir: %w", err)
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
	nodeKey, _, _, err := net.provisionNodeIdentity(byzantineDir, cfg.IdentitySeed, false)
	if err != nil {
		return nil, fmt.Errorf("oasis/byzantine: failed to provision node identity: %w", err)
	}
	if err := cfg.Entity.addNode(nodeKey); err != nil {
		return nil, err
	}

	worker := &Byzantine{
		Node: Node{
			Name:                                     byzantineName,
			net:                                      net,
			dir:                                      byzantineDir,
			termEarlyOk:                              true,
			disableDefaultLogWatcherHandlerFactories: cfg.DisableDefaultLogWatcherHandlerFactories,
			logWatcherHandlerFactories:               cfg.LogWatcherHandlerFactories,
			consensus:                                cfg.Consensus,
		},
		script:          cfg.Script,
		extraArgs:       cfg.ExtraArgs,
		entity:          cfg.Entity,
		consensusPort:   net.nextNodePort,
		p2pPort:         net.nextNodePort + 1,
		activationEpoch: cfg.ActivationEpoch,
	}
	worker.doStartNode = worker.startNode
	copy(worker.NodeID[:], nodeKey[:])

	net.byzantine = append(net.byzantine, worker)
	net.nextNodePort += 2

	if err := net.AddLogWatcher(&worker.Node); err != nil {
		net.logger.Error("failed to add log watcher",
			"err", err,
			"byzantine_name", byzantineName,
		)
		return nil, fmt.Errorf("oasis/byzantine: failed to add log watcher for %s: %w", byzantineName, err)
	}

	return worker, nil
}
