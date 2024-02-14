package oasis

import (
	"fmt"
	"net"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	commonNode "github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/crypto"
)

// Sentry is an Oasis sentry node.
type Sentry struct {
	*Node

	validatorIndices  []int
	computeIndices    []int
	keymanagerIndices []int

	p2pPublicKey  signature.PublicKey
	tlsPublicKey  signature.PublicKey
	tmAddress     string
	consensusPort uint16
	controlPort   uint16
	sentryPort    uint16
}

// SentryCfg is the Oasis sentry node configuration.
type SentryCfg struct {
	NodeCfg

	ValidatorIndices  []int
	ComputeIndices    []int
	KeymanagerIndices []int
}

// TLSCertPath returns the path to the node's TLS certificate.
func (sentry *Sentry) TLSCertPath() string {
	return nodeTLSCertPath(sentry.dir)
}

// GetTLSPubKey returns the sentry TLS public key.
func (sentry *Sentry) GetTLSPubKey() signature.PublicKey {
	return sentry.tlsPublicKey
}

// GetSentryAddress returns the sentry grpc endpoint address.
func (sentry *Sentry) GetSentryAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", sentry.sentryPort)
}

// GetSentryControlAddress returns the sentry control endpoint address.
func (sentry *Sentry) GetSentryControlAddress() string {
	return fmt.Sprintf("127.0.0.1:%d", sentry.controlPort)
}

func (sentry *Sentry) AddArgs(args *argBuilder) error {
	args.
		configureDebugCrashPoints(sentry.crashPointsProbability).
		appendNetwork(sentry.net)

	return nil
}

func (sentry *Sentry) ModifyConfig() error {
	sentry.Config.Consensus.ListenAddress = allInterfacesAddr + ":" + strconv.Itoa(int(sentry.consensusPort))
	sentry.Config.Consensus.ExternalAddress = localhostAddr + ":" + strconv.Itoa(int(sentry.consensusPort))

	if sentry.supplementarySanityInterval > 0 {
		sentry.Config.Consensus.SupplementarySanity.Enabled = true
		sentry.Config.Consensus.SupplementarySanity.Interval = sentry.supplementarySanityInterval
	}

	sentry.Config.Sentry.Enabled = true
	sentry.Config.Sentry.Control.Port = sentry.controlPort

	sentry.AddSeedNodesToConfig()

	validators, err := resolveValidators(sentry.net, sentry.validatorIndices)
	if err != nil {
		return err
	}

	computeWorkers, err := resolveComputeWorkers(sentry.net, sentry.computeIndices)
	if err != nil {
		return err
	}

	keymanagerWorkers, err := resolveKeymanagerWorkers(sentry.net, sentry.keymanagerIndices)
	if err != nil {
		return err
	}

	if len(validators) > 0 {
		var addrs, sentryPubKeys []string

		for _, val := range validators {
			addr := commonNode.ConsensusAddress{
				ID: val.p2pSigner,
				Address: commonNode.Address{
					IP:   net.ParseIP("127.0.0.1"),
					Port: int64(val.consensusPort),
				},
			}
			addrs = append(addrs, addr.String())
			key, _ := val.sentryPubKey.MarshalText()
			sentryPubKeys = append(sentryPubKeys, string(key))
		}

		sentry.Config.Sentry.Control.AuthorizedPubkeys = append(sentry.Config.Sentry.Control.AuthorizedPubkeys, sentryPubKeys...)
		sentry.Config.Consensus.SentryUpstreamAddresses = append(sentry.Config.Consensus.SentryUpstreamAddresses, addrs...)
	}

	if len(computeWorkers) > 0 {
		var tmAddrs, sentryPubKeys []string

		for _, computeWorker := range computeWorkers {
			addr := commonNode.ConsensusAddress{
				ID: computeWorker.p2pSigner,
				Address: commonNode.Address{
					IP:   net.ParseIP("127.0.0.1"),
					Port: int64(computeWorker.consensusPort),
				},
			}
			tmAddrs = append(tmAddrs, addr.String())
			key, _ := computeWorker.sentryPubKey.MarshalText()
			sentryPubKeys = append(sentryPubKeys, string(key))
		}

		sentry.Config.Sentry.Control.AuthorizedPubkeys = append(sentry.Config.Sentry.Control.AuthorizedPubkeys, sentryPubKeys...)
		sentry.Config.Consensus.SentryUpstreamAddresses = append(sentry.Config.Consensus.SentryUpstreamAddresses, tmAddrs...)
	}

	if len(keymanagerWorkers) > 0 {
		var tmAddrs, sentryPubKeys []string

		for _, keymanager := range keymanagerWorkers {
			addr := commonNode.ConsensusAddress{
				ID: keymanager.p2pSigner,
				Address: commonNode.Address{
					IP:   net.ParseIP("127.0.0.1"),
					Port: int64(keymanager.consensusPort),
				},
			}
			tmAddrs = append(tmAddrs, addr.String())
			key, _ := keymanager.sentryPubKey.MarshalText()
			sentryPubKeys = append(sentryPubKeys, string(key))
		}

		sentry.Config.Sentry.Control.AuthorizedPubkeys = append(sentry.Config.Sentry.Control.AuthorizedPubkeys, sentryPubKeys...)
		sentry.Config.Consensus.SentryUpstreamAddresses = append(sentry.Config.Consensus.SentryUpstreamAddresses, tmAddrs...)
	}

	return nil
}

// NewSentry provisions a new sentry node and adds it to the network.
func (net *Network) NewSentry(cfg *SentryCfg) (*Sentry, error) {
	sentryName := fmt.Sprintf("sentry-%d", len(net.sentries))
	host, err := net.GetNamedNode(sentryName, &cfg.NodeCfg)
	if err != nil {
		return nil, err
	}

	// Pre-provision node's identity to pass the sentry node's consensus
	// address to the validator so it can configure the sentry node's consensus
	// address as its consensus address.
	signerFactory, err := fileSigner.NewFactory(host.dir.String(), identity.RequiredSignerRoles...)
	if err != nil {
		net.logger.Error("failed to create sentry signer factory",
			"err", err,
			"sentry_name", sentryName,
		)
		return nil, fmt.Errorf("oasis/sentry: failed to create sentry file signer: %w", err)
	}
	sentryIdentity, err := identity.LoadOrGenerate(host.dir.String(), signerFactory)
	if err != nil {
		net.logger.Error("failed to provision sentry identity",
			"err", err,
			"sentry_name", sentryName,
		)
		return nil, fmt.Errorf("oasis/sentry: failed to provision sentry identity: %w", err)
	}
	sentryP2PPublicKey := sentryIdentity.P2PSigner.Public()
	sentryTLSPublicKey := sentryIdentity.TLSSigner.Public()

	sentry := &Sentry{
		Node:              host,
		validatorIndices:  cfg.ValidatorIndices,
		computeIndices:    cfg.ComputeIndices,
		keymanagerIndices: cfg.KeymanagerIndices,
		p2pPublicKey:      sentryP2PPublicKey,
		tlsPublicKey:      sentryTLSPublicKey,
		tmAddress:         crypto.PublicKeyToCometBFT(&sentryP2PPublicKey).Address().String(),
		consensusPort:     host.getProvisionedPort(nodePortConsensus),
		controlPort:       host.getProvisionedPort("sentry-control"),
		sentryPort:        host.getProvisionedPort("sentry-client"),
	}

	net.sentries = append(net.sentries, sentry)
	host.features = append(host.features, sentry)

	return sentry, nil
}
