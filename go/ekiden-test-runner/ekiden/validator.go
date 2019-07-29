package ekiden

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
)

// Validator is an ekiden validator.
type Validator struct {
	net *Network
	dir *env.Dir

	entity *Entity

	consensusPort uint16
	grpcDebugPort uint16
}

// ValidatorCfg is the ekiden validator provisioning configuration.
type ValidatorCfg struct {
	Entity *Entity
}

func (val *Validator) toGenesisArgs() []string {
	return []string{
		"--node", val.descriptorPath(),
	}
}

func (val *Validator) descriptorPath() string {
	return filepath.Join(val.dir.String(), "node_genesis.json")
}

// SocketPath returns the path to the validator's gRPC socket.
func (val *Validator) SocketPath() string {
	return filepath.Join(val.dir.String(), internalSocketFile)
}

// LogPath returns the path to the node's log.
func (val *Validator) LogPath() string {
	return nodeLogPath(val.dir)
}

func (val *Validator) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(val.consensusPort).
		grpcDebugPort(val.grpcDebugPort).
		storageBackend("client").
		appendNetwork(val.net)

	if err := val.net.startEkidenNode(val.dir, args, "validator"); err != nil {
		return errors.Wrap(err, "ekiden/validator: failed to launch node")
	}

	return nil
}

// NewValidator provisions a new validator and adds it to the network.
func (net *Network) NewValidator(cfg *ValidatorCfg) (*Validator, error) {
	valName := fmt.Sprintf("validator-%d", len(net.validators))

	val := &Validator{
		net:           net,
		entity:        cfg.Entity,
		consensusPort: net.nextNodePort,
		grpcDebugPort: net.nextNodePort + 1,
	}

	var err error
	if val.dir, err = net.baseDir.NewSubDir(valName); err != nil {
		net.logger.Error("failed to create valdiator subdir",
			"err", err,
			"validator_name", valName,
		)
		return nil, errors.Wrap(err, "ekiden/validator: failed to create validator subdir")
	}

	args := []string{
		"registry", "node", "init",
		"--datadir", val.dir.String(),
		"--node.consensus_address", fmt.Sprintf("127.0.0.1:%d", val.consensusPort),
		"--node.expiration", "1000000",
		"--node.role", "validator",
	}
	args = append(args, cfg.Entity.toGenesisArgs()...)

	w, err := val.dir.NewLogWriter("provision.log")
	if err != nil {
		return nil, err
	}
	defer w.Close()

	if err = net.runEkidenBinary(w, args...); err != nil {
		net.logger.Error("failed to provision validator",
			"err", err,
			"validator_name", valName,
		)
		return nil, errors.Wrap(err, "ekiden/validator: failed to provision validator")
	}

	net.validators = append(net.validators, val)
	net.nextNodePort += 2

	return val, nil
}
