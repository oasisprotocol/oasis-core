package oasis

import (
	"fmt"
	netPkg "net"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdRegNode "github.com/oasislabs/oasis-core/go/oasis-node/cmd/registry/node"
)

// Validator is an Oasis validator.
type Validator struct {
	Node

	entity *Entity

	minGasPrice uint64

	sentries []*Sentry

	tmAddress     string
	consensusPort uint16
}

// ValidatorCfg is the Oasis validator provisioning configuration.
type ValidatorCfg struct {
	NodeCfg

	Entity *Entity

	MinGasPrice uint64

	Sentries []*Sentry
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
		debugDontBlameOasis().
		debugAllowTestKeys().
		consensusValidator().
		tendermintCoreListenAddress(val.consensusPort).
		tendermintMinGasPrice(val.minGasPrice).
		storageBackend("client").
		appendNetwork(val.net).
		appendEntity(val.entity)

	if len(val.sentries) > 0 {
		args = args.addSentries(val.sentries).
			addSentriesAsPersistentPeers(val.sentries).
			tendermintDisablePeerExchange()
	}

	var err error
	if val.cmd, val.exitCh, err = val.net.startOasisNode(
		val.dir,
		nil,
		args,
		val.Name,
		false,
		val.restartable,
	); err != nil {
		return fmt.Errorf("oasis/validator: failed to launch node %s: %w", val.Name, err)
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
			Name:                                     valName,
			net:                                      net,
			dir:                                      valDir,
			restartable:                              cfg.Restartable,
			disableDefaultLogWatcherHandlerFactories: cfg.DisableDefaultLogWatcherHandlerFactories,
			logWatcherHandlerFactories:               cfg.LogWatcherHandlerFactories,
		},
		entity:        cfg.Entity,
		minGasPrice:   cfg.MinGasPrice,
		sentries:      cfg.Sentries,
		consensusPort: net.nextNodePort,
	}
	val.doStartNode = val.startNode

	var consensusAddrs []interface{ String() string }
	localhost := netPkg.ParseIP("127.0.0.1")
	if len(val.sentries) > 0 {
		for _, sentry := range val.sentries {
			var consensusAddr node.ConsensusAddress
			consensusAddr.ID = sentry.publicKey
			if err = consensusAddr.Address.FromIP(localhost, sentry.consensusPort); err != nil {
				return nil, fmt.Errorf("oasis/validator: failed to parse IP address: %w", err)
			}
			consensusAddrs = append(consensusAddrs, &consensusAddr)
		}
	} else {
		var consensusAddr node.Address
		if err = consensusAddr.FromIP(localhost, val.consensusPort); err != nil {
			return nil, fmt.Errorf("oasis/validator: failed to parse IP address: %w", err)
		}
		consensusAddrs = append(consensusAddrs, &consensusAddr)
	}

	args := []string{
		"registry", "node", "init",
		"--" + cmdCommon.CfgDataDir, val.dir.String(),
		"--" + cmdRegNode.CfgExpiration, "1",
		"--" + cmdRegNode.CfgRole, "validator",
	}
	for _, v := range consensusAddrs {
		args = append(args, []string{"--" + cmdRegNode.CfgConsensusAddress, v.String()}...)
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

	// Load node's identity, so that we can pass the validator's Tendermint
	// address to sentry node(s) to configure it as a private peer.
	valPublicKey, err := provisionNodeIdentity(valDir)
	if err != nil {
		return nil, errors.Wrap(err, "oasis/validator: failed to provision node identity")
	}
	val.tmAddress = crypto.PublicKeyToTendermint(&valPublicKey).Address().String()
	if err = cfg.Entity.addNode(valPublicKey); err != nil {
		return nil, err
	}

	net.validators = append(net.validators, val)
	net.nextNodePort++

	// Use the first validator as a controller.
	if len(net.validators) == 1 {
		if net.controller, err = NewController(val.SocketPath()); err != nil {
			return nil, errors.Wrap(err, "oasis/validator: failed to create controller")
		}
	}

	if err := net.AddLogWatcher(&val.Node); err != nil {
		net.logger.Error("failed to add log watcher",
			"err", err,
			"validator_name", valName,
		)
		return nil, fmt.Errorf("oasis/validator: failed to add log watcher for %s: %w", valName, err)
	}

	return val, nil
}
