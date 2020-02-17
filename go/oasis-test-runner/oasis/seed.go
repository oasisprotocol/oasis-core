package oasis

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
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
		tendermintCoreListenAddress(seed.consensusPort).
		tendermintSeedMode()

	if err := seed.net.startOasisNode(&seed.Node, nil, args); err != nil {
		return fmt.Errorf("oasis/seed: failed to launch node %s: %w", seed.Name, err)
	}

	return nil
}

func (net *Network) newSeedNode() (*seedNode, error) {
	if net.seedNode != nil {
		return nil, errors.New("oasis/seed: already provisioned")
	}

	// Why, yes, this *could* probably just use Oasis node's integrated seed
	// node as a library, but this is more "realistic" for tests.

	seedName := "seed"

	seedDir, err := net.baseDir.NewSubDir(seedName)
	if err != nil {
		net.logger.Error("failed to create seed node subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "oasis/seed: failed to create seed subdir")
	}

	// Pre-provision the node identity, so that we can figure out what
	// to pass all the actual nodes in advance, instead of having to
	// start the node and fork out to `oasis-node debug tendermint show-node-id`.
	signerFactory, err := fileSigner.NewFactory(seedDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	if err != nil {
		return nil, errors.Wrap(err, "oasis/seed: failed to create seed signer factory")
	}
	seedIdentity, err := identity.LoadOrGenerate(seedDir.String(), signerFactory)
	if err != nil {
		return nil, errors.Wrap(err, "oasis/seed: failed to provision seed identity")
	}
	seedPublicKey := seedIdentity.NodeSigner.Public()

	seedNode := &seedNode{
		Node: Node{
			Name: seedName,
			net:  net,
			dir:  seedDir,
		},
		tmAddress:     crypto.PublicKeyToTendermint(&seedPublicKey).Address().String(),
		consensusPort: net.nextNodePort,
	}
	seedNode.doStartNode = seedNode.startNode
	net.seedNode = seedNode
	net.nextNodePort++

	return seedNode, nil
}
