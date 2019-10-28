package oasis

import (
	"fmt"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
)

// Validator is an Oasis validator.
type Validator struct {
	net *Network
	dir *env.Dir

	entity *Entity

	consensusPort uint16
	grpcDebugPort uint16
}

// ValidatorCfg is the Oasis validator provisioning configuration.
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
	return internalSocketPath(val.dir)
}

// LogPath returns the path to the node's log.
func (val *Validator) LogPath() string {
	return nodeLogPath(val.dir)
}

// IdentityKeyPath returns the path to the node's identity key.
func (val *Validator) IdentityKeyPath() string {
	return nodeIdentityKeyPath(val.dir)
}

// P2PKeyPath returns the path to the node's P2P key.
func (val *Validator) P2PKeyPath() string {
	return nodeP2PKeyPath(val.dir)
}

// ConsensusKeyPath returns the path to the node's consensus key.
func (val *Validator) ConsensusKeyPath() string {
	return nodeConsensusKeyPath(val.dir)
}

func (val *Validator) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		consensusValidator().
		tendermintCoreListenAddress(val.consensusPort).
		grpcDebugPort(val.grpcDebugPort).
		storageBackend("client").
		appendNetwork(val.net).
		appendEntity(val.entity)

	if _, err := val.net.startOasisNode(val.dir, nil, args, "validator", false, false); err != nil {
		return errors.Wrap(err, "oasis/validator: failed to launch node")
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
		return nil, errors.Wrap(err, "oasis/validator: failed to create validator subdir")
	}

	args := []string{
		"registry", "node", "init",
		"--datadir", val.dir.String(),
		"--node.consensus_address", fmt.Sprintf("127.0.0.1:%d", val.consensusPort),
		"--node.expiration", "1",
		"--node.role", "validator",
	}
	args = append(args, cfg.Entity.toGenesisArgs()...)

	w, err := val.dir.NewLogWriter("provision.log")
	if err != nil {
		return nil, err
	}
	defer w.Close()

	if err = net.runNodeBinary(w, args...); err != nil {
		net.logger.Error("failed to provision validator",
			"err", err,
			"validator_name", valName,
		)
		return nil, errors.Wrap(err, "oasis/validator: failed to provision validator")
	}

	net.validators = append(net.validators, val)
	net.nextNodePort += 2

	// Use the first validator as a controller.
	if len(net.validators) == 1 {
		if net.controller, err = NewController(val.SocketPath()); err != nil {
			return nil, errors.Wrap(err, "oasis/validator: failed to create controller")
		}
	}

	return val, nil
}
