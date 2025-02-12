package oasis

import (
	"crypto/ed25519"
	"fmt"
	netPkg "net"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/config"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdRegNode "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/node"
)

const validatorIdentitySeedTemplate = "ekiden node validator %d"

// Validator is an Oasis validator.
type Validator struct {
	*Node

	sentries []*Sentry

	sentryPubKey  signature.PublicKey
	consensusPort uint16
	p2pPort       uint16
}

// ValidatorCfg is the Oasis validator provisioning configuration.
type ValidatorCfg struct {
	NodeCfg

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

// ExportsPath returns the path to the node's exports data dir.
func (val *Validator) ExportsPath() string {
	return nodeExportsPath(val.dir)
}

func (val *Validator) AddArgs(args *argBuilder) error {
	args.
		configureDebugCrashPoints(val.crashPointsProbability).
		appendNetwork(val.net)

	if val.entity.isDebugTestEntity {
		args.appendDebugTestEntity()
	}

	return nil
}

func (val *Validator) ModifyConfig() error {
	val.Config.Mode = config.ModeValidator
	val.Config.Consensus.Validator = true

	val.Config.Consensus.ListenAddress = allInterfacesAddr + ":" + strconv.Itoa(int(val.consensusPort))
	val.Config.Consensus.ExternalAddress = localhostAddr + ":" + strconv.Itoa(int(val.consensusPort))

	if val.supplementarySanityInterval > 0 {
		val.Config.Consensus.SupplementarySanity.Enabled = true
		val.Config.Consensus.SupplementarySanity.Interval = val.supplementarySanityInterval
	}

	val.Config.P2P.Port = val.p2pPort

	if !val.entity.isDebugTestEntity {
		entityID, _ := val.entity.ID().MarshalText() // Cannot fail.
		val.Config.Registration.EntityID = string(entityID)
	}

	if len(val.sentries) > 0 {
		val.Config.Consensus.P2P.DisablePeerExchange = true
		val.AddSentriesToConfig(val.sentries)
	} else {
		val.AddSeedNodesToConfig()
	}

	return nil
}

// NewValidator provisions a new validator and adds it to the network.
func (net *Network) NewValidator(cfg *ValidatorCfg) (*Validator, error) {
	valName := fmt.Sprintf("validator-%d", len(net.validators))
	host, err := net.GetNamedNode(valName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	val := &Validator{
		Node:          host,
		sentries:      cfg.Sentries,
		consensusPort: host.getProvisionedPort(nodePortConsensus),
		p2pPort:       host.getProvisionedPort(nodePortP2P),
	}

	var consensusAddrs []interface{ String() string }
	localhost := netPkg.ParseIP("127.0.0.1")
	if len(val.sentries) > 0 {
		for _, sentry := range val.sentries {
			var consensusAddr node.ConsensusAddress
			consensusAddr.ID = sentry.p2pPublicKey
			if err = consensusAddr.Address.FromIP(localhost, sentry.consensusPort); err != nil {
				return nil, fmt.Errorf("oasis/validator: failed to parse sentry IP address: %w", err)
			}
			consensusAddrs = append(consensusAddrs, &consensusAddr)
		}
	} else {
		var consensusAddr node.Address
		if err = consensusAddr.FromIP(localhost, val.consensusPort); err != nil {
			return nil, fmt.Errorf("oasis/validator: failed to parse consensus IP address: %w", err)
		}
		consensusAddrs = append(consensusAddrs, &consensusAddr)
	}

	var p2pAddr node.Address
	if err = p2pAddr.FromIP(localhost, val.p2pPort); err != nil {
		return nil, fmt.Errorf("oasis/validator: failed to parse P2P IP address: %w", err)
	}

	// Load node's identity, so that we can pass the validator's CometBFT
	// address to sentry node(s) to configure it as a private peer.
	err = host.setProvisionedIdentity(fmt.Sprintf(validatorIdentitySeedTemplate, len(net.validators)))
	if err != nil {
		return nil, fmt.Errorf("oasis/validator: failed to provision node identity: %w", err)
	}

	// Sentry client cert.
	pk, ok := host.sentryCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oasis/validator: bad sentry client public key type (expected: Ed25519 got: %T)", host.sentryCert.PublicKey)
	}
	if err = val.sentryPubKey.UnmarshalBinary(pk[:]); err != nil {
		return nil, fmt.Errorf("oasis/validator: sentry client public key unmarshal failure: %w", err)
	}

	// Write a dummy config file with just the data dir to make init happy.
	// (It will get overwritten with the proper config before the node is started.)
	cfgFile := filepath.Join(val.DataDir(), "config.yaml")
	defCfg := config.DefaultConfig()
	defCfg.Common.DataDir = val.DataDir()
	cfgString, err := yaml.Marshal(&defCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config file: %w", err)
	}
	if err = os.WriteFile(cfgFile, cfgString, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write config file '%s': %w", cfgFile, err)
	}

	args := []string{
		"registry", "node", "init",
		"--" + cmdCommon.CfgConfigFile, val.ConfigFile(),
		"--" + cmdRegNode.CfgExpiration, "1",
		"--" + cmdRegNode.CfgRole, "validator",
		"--" + cmdRegNode.CfgEntityID, cfg.Entity.ID().String(),
		"--" + cmdRegNode.CfgP2PAddress, p2pAddr.String(),
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
		return nil, fmt.Errorf("oasis/validator: failed to provision validator: %w", err)
	}

	net.validators = append(net.validators, val)
	host.features = append(host.features, val)
	host.hasValidators = true

	return val, nil
}
