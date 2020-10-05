package oasis

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
)

// SeedCfg is the Oasis seed node configuration.
type SeedCfg struct {
	DisableAddrBookFromGenesis bool
}

// Seed is an Oasis seed node.
type Seed struct { // nolint: maligned
	Node

	disableAddrBookFromGenesis bool

	tmAddress     string
	consensusPort uint16
}

func (seed *Seed) startNode() error {
	otherSeeds := []*Seed{}
	for _, s := range seed.net.seeds {
		if s.Name == seed.Name {
			continue
		}
		otherSeeds = append(otherSeeds, s)
	}

	args := newArgBuilder().
		debugDontBlameOasis().
		debugAllowTestKeys().
		workerCertificateRotation(true).
		tendermintCoreAddress(seed.consensusPort).
		appendSeedNodes(otherSeeds).
		tendermintSeedMode()

	if seed.disableAddrBookFromGenesis {
		args = args.tendermintSeedDisableAddrBookFromGenesis()
	}

	if err := seed.net.startOasisNode(&seed.Node, nil, args); err != nil {
		return fmt.Errorf("oasis/seed: failed to launch node %s: %w", seed.Name, err)
	}

	return nil
}

// NewSeed provisions a new seed node and adds it to the network.
func (net *Network) NewSeed(cfg *SeedCfg) (*Seed, error) {
	seedName := fmt.Sprintf("seed-%d", len(net.seeds))

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

	seedNode := &Seed{
		Node: Node{
			Name: seedName,
			net:  net,
			dir:  seedDir,
		},
		disableAddrBookFromGenesis: cfg.DisableAddrBookFromGenesis,
		tmAddress:                  crypto.PublicKeyToTendermint(&seedP2PPublicKey).Address().String(),
		consensusPort:              net.nextNodePort,
	}
	seedNode.doStartNode = seedNode.startNode
	net.seeds = append(net.seeds, seedNode)
	net.nextNodePort++

	return seedNode, nil
}
