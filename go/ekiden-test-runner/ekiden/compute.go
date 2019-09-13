package ekiden

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

// Compute is a ekiden compute node
type Compute struct {
	net *Network
	dir *env.Dir

	entity *Entity

	consensusPort uint16
	clientPort    uint16
	p2pPort       uint16
}

// ComputeCfg is the ekiden compute node configuration.
type ComputeCfg struct {
	Entity *Entity
}

// LogPath returnbs the path to the compute node's log.
func (worker *Compute) LogPath() string {
	return nodeLogPath(worker.dir)
}

func (worker *Compute) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(worker.consensusPort).
		roothashTendermintIndexBlocks().
		storageCachingclient(worker.dir).
		workerClientPort(worker.clientPort).
		workerP2pPort(worker.p2pPort).
		workerComputeEnabled().
		workerComputeBackend("sandboxed"). // XXX
		workerComputeRuntimeLoader(worker.net.cfg.RuntimeLoaderBinary).
		workerMergeEnabled().
		workerTxnschedulerEnabled().
		workerTxnschedulerBatchingMaxBatchSize(1).
		appendNetwork(worker.net).
		appendEntity(worker.entity)
	for _, v := range worker.net.runtimes {
		args = args.appendComputeNodeRuntime(v)
	}

	if err := worker.net.startEkidenNode(worker.dir, nil, args, "compute"); err != nil {
		return errors.Wrap(err, "ekiden/compute: failed to launch node")
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
		return nil, errors.Wrap(err, "ekiden/compute: failed to create compute subdir")
	}

	worker := &Compute{
		net:           net,
		dir:           computeDir,
		entity:        cfg.Entity,
		consensusPort: net.nextNodePort,
		clientPort:    net.nextNodePort + 1,
		p2pPort:       net.nextNodePort + 2,
	}

	net.computeWorkers = append(net.computeWorkers, worker)
	net.nextNodePort += 3

	return worker, nil
}
