package oasis

import (
	"fmt"
	netPkg "net"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/node"
)

// Validator is an Oasis validator.
type Validator struct {
	Node

	entity *Entity

	minGasPrice uint64

	consensusPort uint16
	grpcDebugPort uint16
}

// ValidatorCfg is the Oasis validator provisioning configuration.
type ValidatorCfg struct {
	NodeCfg
	Entity *Entity

	MinGasPrice uint64
}

func (val *Validator) toGenesisArgs() []string {
	return []string{
		"--node", val.descriptorPath(),
	}
}

func (val *Validator) descriptorPath() string {
	return filepath.Join(val.dir.String(), "node_genesis.json")
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

// Exports path returns the path to the node's exports data dir.
func (val *Validator) ExportsPath() string {
	return nodeExportsPath(val.dir)
}

func (val *Validator) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		consensusValidator().
		tendermintCoreListenAddress(val.consensusPort).
		tendermintMinGasPrice(val.minGasPrice).
		grpcDebugPort(val.grpcDebugPort).
		storageBackend("client").
		appendNetwork(val.net).
		appendEntity(val.entity)

	var err error
	if val.cmd, val.exitCh, err = val.net.startOasisNode(val.dir, nil, args, "validator", false, val.restartable); err != nil {
		return errors.Wrap(err, "oasis/validator: failed to launch node")
	}

	return nil
}

// NewValidator provisions a new validator and adds it to the network.
func (net *Network) NewValidator(cfg *ValidatorCfg) (*Validator, error) {
	valName := fmt.Sprintf("validator-%d", len(net.validators))

	valDir, err := net.baseDir.NewSubDir(valName)
	if err != nil {
		net.logger.Error("failed to create validator subdir",
			"err", err,
			"validator_name", valName,
		)
		return nil, fmt.Errorf("oasis/validator: failed to create validator subdir: %w", err)
	}

	val := &Validator{
		Node: Node{
			net:         net,
			dir:         valDir,
			restartable: cfg.Restartable,
		},
		entity:        cfg.Entity,
		minGasPrice:   cfg.MinGasPrice,
		consensusPort: net.nextNodePort,
		grpcDebugPort: net.nextNodePort + 1,
	}
	val.doStartNode = val.startNode

	var valConsensusAddr node.Address
	if err = valConsensusAddr.FromIP(netPkg.ParseIP("127.0.0.1"), val.consensusPort); err != nil {
		return nil, fmt.Errorf("oasis/validator: failed to parse IP: %w", err)
	}

	args := []string{
		"registry", "node", "init",
		"--datadir", val.dir.String(),
		"--node.consensus_address", valConsensusAddr.String(),
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
