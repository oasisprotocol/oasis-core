package ekiden

import (
	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/tendermint/crypto"
)

type seedNode struct {
	net *Network
	dir *env.Dir

	tmAddress     string
	consensusPort uint16
}

func (seed *seedNode) startNode() error {
	args := newArgBuilder().
		debugAllowTestKeys().
		tendermintCoreListenAddress(seed.consensusPort).
		tendermintSeedMode()

	if err := seed.net.startEkidenNode(seed.dir, nil, args, "seed"); err != nil {
		return errors.Wrap(err, "ekiden/seed: failed to launch node")
	}

	return nil
}

func (net *Network) newSeedNode() (*seedNode, error) {
	if net.seedNode != nil {
		return nil, errors.New("ekiden/seed: already provisioned")
	}

	// Why, yes, this *could* probably just use ekiden's integrated seed node
	// as a library, but this is more "realistic" for tests.

	seedDir, err := net.baseDir.NewSubDir("seed")
	if err != nil {
		net.logger.Error("failed to create seed node subdir",
			"err", err,
		)
		return nil, errors.Wrap(err, "ekiden/seed: failed to create seed subdir")
	}

	// Pre-provision the node identity, so that we can figure out what
	// to pass all the actual nodes in advance, instead of having to
	// start the node and fork out to `ekiden debug tendermint show-node-id`.
	signerFactory := fileSigner.NewFactory(seedDir.String(), signature.SignerNode, signature.SignerP2P, signature.SignerEntity)
	seedIdentity, err := identity.LoadOrGenerate(seedDir.String(), signerFactory)
	if err != nil {
		return nil, errors.Wrap(err, "ekiden/seed: failed to provision seed identity")
	}
	seedPublicKey := seedIdentity.NodeSigner.Public()

	seedNode := &seedNode{
		net:           net,
		dir:           seedDir,
		tmAddress:     crypto.PublicKeyToTendermint(&seedPublicKey).Address().String(),
		consensusPort: net.nextNodePort,
	}
	net.seedNode = seedNode
	net.nextNodePort++

	return seedNode, nil
}
