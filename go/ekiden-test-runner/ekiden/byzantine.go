package ekiden

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/epochtime/tendermint_mock"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

// Byzantine is an ekiden byzantine node.
type Byzantine struct {
	net *Network
	dir *env.Dir

	script string
	entity *Entity

	consensusPort uint16
	p2pPort       uint16
}

// ByzantineCfg is the ekiden byzantine node configuration.
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
		}
	}

	if _, err := worker.net.startEkidenNode(worker.dir, []string{"debug", "byzantine", worker.script}, args, "byzantine", true, false); err != nil {
		return errors.Wrap(err, "ekiden/byzantine: failed to launch node")
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
		return nil, errors.Wrap(err, "ekiden/byzantine: failed to create byzantine node subdir")
	}

	if cfg.Script == "" {
		return nil, errors.New("ekiden/byzantine: empty script name")
	}

	// Generate a deterministic identity as the Byzantine node scripts usually
	// require specific roles in the first round.
	if cfg.IdentitySeed == "" {
		return nil, errors.New("ekiden/byzantine: empty identity seed")
	}
	if err := net.generateDeterministicNodeIdentity(byzantineDir, cfg.IdentitySeed); err != nil {
		return nil, errors.Wrap(err, "ekiden/byzantine: failed to generate deterministic identity")
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
