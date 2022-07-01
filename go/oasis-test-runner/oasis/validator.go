package oasis

import (
	"crypto/ed25519"
	"fmt"
	netPkg "net"
	"path/filepath"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdRegNode "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/registry/node"
)

const validatorIdentitySeedTemplate = "ekiden node validator %d"

// Validator is an Oasis validator.
type Validator struct {
	*Node

	sentries []*Sentry

	tmAddress     string
	sentryPubKey  signature.PublicKey
	consensusPort uint16
	clientPort    uint16

	disableCertRotation bool
}

// ValidatorCfg is the Oasis validator provisioning configuration.
type ValidatorCfg struct {
	NodeCfg

	Sentries []*Sentry

	DisableCertRotation bool
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

// ExternalGRPCAddress returns the address of the node's external gRPC server.
func (val *Validator) ExternalGRPCAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", val.clientPort)
}

func (val *Validator) AddArgs(args *argBuilder) error {
	args.debugDontBlameOasis().
		debugAllowRoot().
		debugAllowTestKeys().
		debugSetRlimit().
		debugEnableProfiling(val.Node.pprofPort).
		workerCertificateRotation(!val.disableCertRotation).
		consensusValidator().
		tendermintCoreAddress(val.consensusPort).
		tendermintMinGasPrice(val.consensus.MinGasPrice).
		tendermintSubmissionGasPrice(val.consensus.SubmissionGasPrice).
		tendermintPrune(val.consensus.PruneNumKept, val.consensus.PruneInterval).
		tendermintRecoverCorruptedWAL(val.consensus.TendermintRecoverCorruptedWAL).
		configureDebugCrashPoints(val.crashPointsProbability).
		tendermintSupplementarySanity(val.supplementarySanityInterval).
		appendNetwork(val.net).
		appendEntity(val.entity)

	if len(val.sentries) > 0 {
		args.addSentries(val.sentries).
			tendermintDisablePeerExchange()
	} else {
		args.appendSeedNodes(val.net.seeds)
	}
	if val.consensus.EnableConsensusRPCWorker {
		args.workerClientPort(val.clientPort).
			workerConsensusRPCEnabled()
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
		Node:                host,
		sentries:            cfg.Sentries,
		consensusPort:       host.getProvisionedPort(nodePortConsensus),
		clientPort:          host.getProvisionedPort(nodePortClient),
		disableCertRotation: cfg.DisableCertRotation,
	}

	var consensusAddrs []interface{ String() string }
	localhost := netPkg.ParseIP("127.0.0.1")
	if len(val.sentries) > 0 {
		for _, sentry := range val.sentries {
			var consensusAddr node.ConsensusAddress
			consensusAddr.ID = sentry.p2pPublicKey
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

	// Load node's identity, so that we can pass the validator's Tendermint
	// address to sentry node(s) to configure it as a private peer.
	err = host.setProvisionedIdentity(false, fmt.Sprintf(validatorIdentitySeedTemplate, len(net.validators)))
	if err != nil {
		return nil, fmt.Errorf("oasis/validator: failed to provision node identity: %w", err)
	}
	val.tmAddress = crypto.PublicKeyToTendermint(&host.p2pSigner).Address().String()

	// Sentry client cert.
	pk, ok := host.sentryCert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("oasis/validator: bad sentry client public key type (expected: Ed25519 got: %T)", host.sentryCert.PublicKey)
	}
	if err = val.sentryPubKey.UnmarshalBinary(pk[:]); err != nil {
		return nil, fmt.Errorf("oasis/validator: sentry client public key unmarshal failure: %w", err)
	}

	args := []string{
		"registry", "node", "init",
		"--" + cmdCommon.CfgDataDir, val.dir.String(),
		"--" + cmdRegNode.CfgExpiration, "1",
		"--" + cmdRegNode.CfgRole, "validator",
		"--" + cmdRegNode.CfgEntityID, cfg.Entity.ID().String(),
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
