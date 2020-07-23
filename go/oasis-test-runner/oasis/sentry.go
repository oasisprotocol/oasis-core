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
	Node

	validatorIndices  []int
	storageIndices    []int
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
	StorageIndices    []int
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

func (sentry *Sentry) startNode() error {
	validators, err := resolveValidators(sentry.net, sentry.validatorIndices)
	if err != nil {
		return err
	}

	storageWorkers, err := resolveStorageWorkers(sentry.net, sentry.storageIndices)
	if err != nil {
		return err
	}

	keymanagerWorkers, err := resolveKeymanagerWorkers(sentry.net, sentry.keymanagerIndices)
	if err != nil {
		return err
	}

	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		workerCertificateRotation(false).
		workerSentryEnabled().
		workerSentryControlPort(sentry.controlPort).
		tendermintCoreListenAddress(sentry.consensusPort).
		tendermintPrune(sentry.consensus.PruneNumKept).
		appendNetwork(sentry.net).
		appendSeedNodes(sentry.net).
		internalSocketAddress(sentry.net.validators[0].SocketPath())

	if len(validators) > 0 {
		args = args.addValidatorsAsSentryUpstreams(validators)
	}

	if len(storageWorkers) > 0 || len(keymanagerWorkers) > 0 {
		args = args.workerGrpcSentryEnabled().
			workerSentryGrpcClientAddress([]string{fmt.Sprintf("127.0.0.1:%d", sentry.sentryPort)}).
			workerSentryGrpcClientPort(sentry.sentryPort)
	}

	if len(storageWorkers) > 0 {
		args = args.addSentryStorageWorkers(storageWorkers)
	}

	if len(keymanagerWorkers) > 0 {
		args = args.addSentryKeymanagerWorkers(keymanagerWorkers)
	}

	if err = sentry.net.startOasisNode(&sentry.Node, nil, args); err != nil {
		return fmt.Errorf("oasis/sentry: failed to launch node %s: %w", sentry.Name, err)
	}

	return nil
}

// NewSentry provisions a new sentry node and adds it to the network.
func (net *Network) NewSentry(cfg *SentryCfg) (*Sentry, error) {
	sentryName := fmt.Sprintf("sentry-%d", len(net.sentries))

	sentryDir, err := net.baseDir.NewSubDir(sentryName)
	if err != nil {
		net.logger.Error("failed to create sentry subdir",
			"err", err,
			"sentry_name", sentryName,
		)
		return nil, fmt.Errorf("oasis/sentry: failed to create sentry subdir: %w", err)
	}

	// Pre-provision node's identity to pass the sentry node's consensus
	// address to the validator so it can configure the sentry node's consensus
	// address as its consensus address.
	signerFactory, err := fileSigner.NewFactory(sentryDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if err != nil {
		net.logger.Error("failed to create sentry signer factory",
			"err", err,
			"sentry_name", sentryName,
		)
		return nil, fmt.Errorf("oasis/sentry: failed to create sentry file signer: %w", err)
	}
	sentryIdentity, err := identity.LoadOrGenerate(sentryDir.String(), signerFactory, true)
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
		Node: Node{
			Name:                                     sentryName,
			net:                                      net,
			dir:                                      sentryDir,
			disableDefaultLogWatcherHandlerFactories: cfg.DisableDefaultLogWatcherHandlerFactories,
			logWatcherHandlerFactories:               cfg.LogWatcherHandlerFactories,
		},
		validatorIndices:  cfg.ValidatorIndices,
		storageIndices:    cfg.StorageIndices,
		keymanagerIndices: cfg.KeymanagerIndices,
		p2pPublicKey:      sentryP2PPublicKey,
		tlsPublicKey:      sentryTLSPublicKey,
		tmAddress:         crypto.PublicKeyToTendermint(&sentryP2PPublicKey).Address().String(),
		consensusPort:     net.nextNodePort,
		controlPort:       net.nextNodePort + 1,
		sentryPort:        net.nextNodePort + 2,
	}
	sentry.doStartNode = sentry.startNode

	net.sentries = append(net.sentries, sentry)
	net.nextNodePort += 3

	if err := net.AddLogWatcher(&sentry.Node); err != nil {
		net.logger.Error("failed to add log watcher",
			"err", err,
			"sentry_name", sentryName,
		)
		return nil, fmt.Errorf("oasis/sentry: failed to add log watcher for %s: %w", sentryName, err)
	}

	return sentry, nil
}
