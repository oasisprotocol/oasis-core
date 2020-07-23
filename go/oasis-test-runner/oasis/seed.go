package oasis

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
)

type seedNode struct {
	Node

	tmAddress     string
	consensusPort uint16
}

func (seed *seedNode) startNode() error {
	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		workerCertificateRotation(true).
		tendermintCoreListenAddress(seed.consensusPort).
		tendermintSeedMode()

	if err := seed.net.startOasisNode(&seed.Node, nil, args); err != nil {
		return fmt.Errorf("oasis/seed: failed to launch node %s: %w", seed.Name, err)
	}

	return nil
}

func (net *Network) newSeedNode() (*seedNode, error) {
	if net.seedNode != nil {
		return nil, fmt.Errorf("oasis/seed: already provisioned")
	}

	// Why, yes, this *could* probably just use Oasis node's integrated seed
	// node as a library, but this is more "realistic" for tests.

	seedName := "seed"

	seedDir, err := net.baseDir.NewSubDir(seedName)
	if err != nil {
		net.logger.Error("failed to create seed node subdir",
			"err", err,
		)
		return nil, fmt.Errorf("oasis/seed: failed to create seed subdir: %w", err)
	}

	// Pre-provision the node identity, so that we can figure out what
	// to pass all the actual nodes in advance, instead of having to
	// start the node and fork out to `oasis-node debug tendermint show-node-id`.
	signerFactory, err := fileSigner.NewFactory(seedDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if err != nil {
		return nil, fmt.Errorf("oasis/seed: failed to create seed signer factory: %w", err)
	}
	seedIdentity, err := identity.LoadOrGenerate(seedDir.String(), signerFactory, false)
	if err != nil {
		return nil, fmt.Errorf("oasis/seed: failed to provision seed identity: %w", err)
	}
	seedP2PPublicKey := seedIdentity.P2PSigner.Public()

	seedNode := &seedNode{
		Node: Node{
			Name: seedName,
			net:  net,
			dir:  seedDir,
		},
		tmAddress:     crypto.PublicKeyToTendermint(&seedP2PPublicKey).Address().String(),
		consensusPort: net.nextNodePort,
	}
	seedNode.doStartNode = seedNode.startNode
	net.seedNode = seedNode
	net.nextNodePort++

	return seedNode, nil
}
