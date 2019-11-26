package oasis

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

// Byzantine is an Oasis byzantine node.
type Byzantine struct {
	Node

	script string
	entity *Entity

	consensusPort uint16
	p2pPort       uint16
}

// ByzantineCfg is the Oasis byzantine node configuration.
type ByzantineCfg struct {
	NodeCfg

	Script       string
	IdentitySeed string
	Entity       *Entity
}

func (worker *Byzantine) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		tendermintCoreListenAddress(worker.consensusPort).
		tendermintDebugAddrBookLenient().
		workerP2pPort(worker.p2pPort).
		appendSeedNodes(worker.net).
		appendEntity(worker.entity)

	for _, v := range worker.net.Runtimes() {
		if v.kind == registry.KindCompute && v.teeHardware == node.TEEHardwareIntelSGX {
			args = args.byzantineFakeSGX()
			args = args.byzantineVersionFakeEnclaveID(v)
		}
	}

	var err error
	if worker.cmd, worker.exitCh, err = worker.net.startOasisNode(worker.dir, []string{"debug", "byzantine", worker.script}, args, "byzantine", true, false); err != nil {
		return errors.Wrap(err, "oasis/byzantine: failed to launch node")
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
		return nil, errors.Wrap(err, "oasis/byzantine: failed to create byzantine node subdir")
	}

	if cfg.Script == "" {
		return nil, errors.New("oasis/byzantine: empty script name")
	}

	// Generate a deterministic identity as the Byzantine node scripts usually
	// require specific roles in the first round.
	if cfg.IdentitySeed == "" {
		return nil, errors.New("oasis/byzantine: empty identity seed")
	}
	if err = net.generateDeterministicNodeIdentity(byzantineDir, cfg.IdentitySeed); err != nil {
		return nil, errors.Wrap(err, "oasis/byzantine: failed to generate deterministic identity")
	}

	// Pre-provision the node identity so that we can update the entity.
	publicKey, err := provisionNodeIdentity(byzantineDir)
	if err != nil {
		return nil, errors.Wrap(err, "oasis/byzantine: failed to provision node identity")
	}
	if err := cfg.Entity.addNode(publicKey); err != nil {
		return nil, err
	}

	worker := &Byzantine{
		Node: Node{
			net: net,
			dir: byzantineDir,
		},
		script:        cfg.Script,
		entity:        cfg.Entity,
		consensusPort: net.nextNodePort,
		p2pPort:       net.nextNodePort + 1,
	}
	worker.doStartNode = worker.startNode

	net.byzantine = append(net.byzantine, worker)
	net.nextNodePort += 2

	return worker, nil
}
