package oasis

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/epochtime/tendermint_mock"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

// Byzantine is an Oasis byzantine node.
type Byzantine struct {
	net *Network
	dir *env.Dir

	script string
	entity *Entity

	consensusPort uint16
	p2pPort       uint16
}

// ByzantineCfg is the Oasis byzantine node configuration.
type ByzantineCfg struct {
	Script       string
	IdentitySeed string
	Entity       *Entity
}

// LogPath returns the path to the byzantine node's log.
func (worker *Byzantine) LogPath() string {
	return nodeLogPath(worker.dir)
}

func (worker *Byzantine) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(worker.consensusPort).
		tendermintConsensusTimeoutCommit(worker.net.cfg.ConsensusTimeoutCommit).
		tendermintDebugAddrBookLenient().
		workerP2pPort(worker.p2pPort).
		appendSeedNodes(worker.net).
		appendEntity(worker.entity)

	if worker.net.cfg.EpochtimeBackend == tendermintmock.BackendName {
		args = args.byzantineMockEpochtime()
	}

	for _, v := range worker.net.Runtimes() {
		if v.kind == registry.KindCompute && v.teeHardware == node.TEEHardwareIntelSGX {
			args = args.byzantineFakeSGX()
			args = args.byzantineVersionFakeEnclaveID(v)
		}
	}

	if _, err := worker.net.startOasisNode(worker.dir, []string{"debug", "byzantine", worker.script}, args, "byzantine", true, false); err != nil {
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
	if err := net.generateDeterministicNodeIdentity(byzantineDir, cfg.IdentitySeed); err != nil {
		return nil, errors.Wrap(err, "oasis/byzantine: failed to generate deterministic identity")
	}

	worker := &Byzantine{
		net:           net,
		dir:           byzantineDir,
		script:        cfg.Script,
		entity:        cfg.Entity,
		consensusPort: net.nextNodePort,
		p2pPort:       net.nextNodePort + 1,
	}

	net.byzantine = append(net.byzantine, worker)
	net.nextNodePort += 2

	return worker, nil
}
