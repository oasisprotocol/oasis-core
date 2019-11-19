package oasis

import (
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
)

// Sentry is an Oasis sentry node.
type Sentry struct {
	Node

	validatorIndices []int

	publicKey     signature.PublicKey
	tmAddress     string
	consensusPort uint16
	controlPort   uint16
}

// SentryCfg is the Oasis sentry node configuration.
type SentryCfg struct {
	ValidatorIndices []int
}

// TLSCertPath returns the path to the node's TLS certificate.
func (sentry *Sentry) TLSCertPath() string {
	return nodeTLSCertPath(sentry.dir)
}

func (sentry *Sentry) startNode() error {
	validators, err := resolveValidators(sentry.net, sentry.validatorIndices)
	if err != nil {
		return err
	}

	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		workerSentryEnabled().
		workerSentryControlPort(sentry.controlPort).
		tendermintCoreListenAddress(sentry.consensusPort).
		appendNetwork(sentry.net).
		addValidatorsAsPrivatePeers(validators)

	if sentry.cmd, _, err = sentry.net.startOasisNode(sentry.dir, nil, args, sentry.Name, false, false); err != nil {
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
	signerFactory := fileSigner.NewFactory(sentryDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	sentryIdentity, err := identity.LoadOrGenerate(sentryDir.String(), signerFactory)
	if err != nil {
		net.logger.Error("failed to provision sentry identity",
			"err", err,
			"sentry_name", sentryName,
		)
		return nil, fmt.Errorf("oasis/sentry: failed to provision sentry identity: %w", err)
	}
	sentryPublicKey := sentryIdentity.NodeSigner.Public()

	sentry := &Sentry{
		Node: Node{
			Name: sentryName,
			net:  net,
			dir:  sentryDir,
		},
		validatorIndices: cfg.ValidatorIndices,
		publicKey:        sentryPublicKey,
		tmAddress:        crypto.PublicKeyToTendermint(&sentryPublicKey).Address().String(),
		consensusPort:    net.nextNodePort,
		controlPort:      net.nextNodePort + 1,
	}
	sentry.doStartNode = sentry.startNode

	net.sentries = append(net.sentries, sentry)
	net.nextNodePort += 2

	return sentry, nil
}
