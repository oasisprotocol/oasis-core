package oasis

import (
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

	var err error
	if seed.cmd, seed.exitCh, err = seed.net.startOasisNode(seed.dir, nil, args, "seed", false, false); err != nil {
		return errors.Wrap(err, "oasis/seed: failed to launch node")
	}

	return nil
}

func (net *Network) newSeedNode() (*seedNode, error) {
	if net.seedNode != nil {
		return nil, errors.New("oasis/seed: already provisioned")
	}

	// Why, yes, this *could* probably just use Oasis node's integrated seed
	// node as a library, but this is more "realistic" for tests.

	seedDir, err := net.baseDir.NewSubDir("seed")
	if err != nil {
		net.logger.Error("failed to create seed node subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "oasis/seed: failed to create seed subdir")
	}

	// Pre-provision the node identity, so that we can figure out what
	// to pass all the actual nodes in advance, instead of having to
	// start the node and fork out to `oasis-node debug tendermint show-node-id`.
	signerFactory := fileSigner.NewFactory(seedDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerConsensus)
	seedIdentity, err := identity.LoadOrGenerate(seedDir.String(), signerFactory)
	if err != nil {
		return nil, errors.Wrap(err, "oasis/seed: failed to provision seed identity")
	}
	seedPublicKey := seedIdentity.NodeSigner.Public()

	seedNode := &seedNode{
		Node: Node{
			net: net,
			dir: seedDir,
		},
		tmAddress:     crypto.PublicKeyToTendermint(&seedPublicKey).Address().String(),
		consensusPort: net.nextNodePort,
	}
	seedNode.doStartNode = seedNode.startNode
	net.seedNode = seedNode
	net.nextNodePort++

	return seedNode, nil
}
