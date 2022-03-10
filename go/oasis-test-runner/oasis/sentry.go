package oasis

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
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

	args.debugDontBlameOasis().
		debugAllowRoot().
		debugAllowTestKeys().
		debugSetRlimit().
		debugEnableProfiling(sentry.Node.pprofPort).
		workerCertificateRotation(false).
		workerSentryEnabled().
		workerSentryControlPort(sentry.controlPort).
		tendermintCoreAddress(sentry.consensusPort).
		tendermintPrune(sentry.consensus.PruneNumKept, sentry.consensus.PruneInterval).
		tendermintRecoverCorruptedWAL(sentry.consensus.TendermintRecoverCorruptedWAL).
		configureDebugCrashPoints(sentry.crashPointsProbability).
		tendermintSupplementarySanity(sentry.supplementarySanityInterval).
		appendNetwork(sentry.net).
		appendSeedNodes(sentry.net.seeds).
		internalSocketAddress(sentry.net.validators[0].SocketPath())

	if len(validators) > 0 {
		args.addValidatorsAsSentryUpstreams(validators)
	}

	if len(computeWorkers) > 0 || len(keymanagerWorkers) > 0 {
		args.workerGrpcSentryEnabled().
			workerSentryGrpcClientAddress([]string{fmt.Sprintf("127.0.0.1:%d", sentry.sentryPort)}).
			workerSentryGrpcClientPort(sentry.sentryPort)
	}

	if len(computeWorkers) > 0 {
		args.addSentryComputeWorkers(computeWorkers)
	}

	if len(keymanagerWorkers) > 0 {
		args.addSentryKeymanagerWorkers(keymanagerWorkers)
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
	sentryIdentity, err := identity.LoadOrGenerate(host.dir.String(), signerFactory, true)
	if err != nil {
		net.logger.Error("failed to provision sentry identity",
			"err", err,
			"sentry_name", sentryName,
		)
		return nil, fmt.Errorf("oasis/sentry: failed to provision sentry identity: %w", err)
	}
	sentryP2PPublicKey := sentryIdentity.P2PSigner.Public()
	sentryTLSPublicKey := sentryIdentity.GetTLSSigner().Public()

	sentry := &Sentry{
		Node:              host,
		validatorIndices:  cfg.ValidatorIndices,
		computeIndices:    cfg.ComputeIndices,
		keymanagerIndices: cfg.KeymanagerIndices,
		p2pPublicKey:      sentryP2PPublicKey,
		tlsPublicKey:      sentryTLSPublicKey,
		tmAddress:         crypto.PublicKeyToTendermint(&sentryP2PPublicKey).Address().String(),
		consensusPort:     host.getProvisionedPort(nodePortConsensus),
		controlPort:       host.getProvisionedPort("sentry-control"),
		sentryPort:        host.getProvisionedPort("sentry-client"),
	}

	net.sentries = append(net.sentries, sentry)
	host.features = append(host.features, sentry)

	return sentry, nil
}
