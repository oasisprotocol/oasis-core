package oasis

import (
	"fmt"
	"strconv"

	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/config"
)

// SeedCfg is the Oasis seed node configuration.
type SeedCfg struct {
	Name string

	DisableAddrBookFromGenesis bool
}

// Seed is an Oasis seed node.
type Seed struct {
	*Node

	disableAddrBookFromGenesis bool

	consensusPort  uint16
	libp2pSeedPort uint16
}

func (seed *Seed) AddArgs(*argBuilder) error {
	return nil
}

func (seed *Seed) ModifyConfig() error {
	seed.Config.Mode = config.ModeSeed

	seed.Config.Consensus.ListenAddress = allInterfacesAddr + ":" + strconv.Itoa(int(seed.consensusPort))
	seed.Config.Consensus.ExternalAddress = localhostAddr + ":" + strconv.Itoa(int(seed.consensusPort))

	if seed.disableAddrBookFromGenesis {
		seed.Config.Consensus.Debug.DisableAddrBookFromGenesis = true
	}

	seed.Config.P2P.Port = seed.libp2pSeedPort

	seed.AddSeedNodesToConfigExcept(seed.Name)

	return nil
}

// NewSeed provisions a new seed node and adds it to the network.
func (net *Network) NewSeed(cfg *SeedCfg) (*Seed, error) {
	seedName := fmt.Sprintf("seed-%d", len(net.seeds))
	host, err := net.GetNamedNode(seedName, nil)
	if err != nil {
		return nil, err
	}

	// Pre-provision the node identity, so that we can figure out what
	// to pass all the actual nodes in advance, instead of having to
	// start the node and fork out to `oasis-node debug cometbft show-node-id`.
	signerFactory, err := fileSigner.NewFactory(host.dir.String(), identity.RequiredSignerRoles...)
	if err != nil {
		return nil, fmt.Errorf("oasis/seed: failed to create seed signer factory: %w", err)
	}
	seedIdentity, err := identity.LoadOrGenerate(host.dir.String(), signerFactory)
	if err != nil {
		return nil, fmt.Errorf("oasis/seed: failed to provision seed identity: %w", err)
	}
	host.p2pSigner = seedIdentity.P2PSigner.Public()

	seedNode := &Seed{
		Node:                       host,
		disableAddrBookFromGenesis: cfg.DisableAddrBookFromGenesis,
		consensusPort:              host.getProvisionedPort(nodePortConsensus),
		libp2pSeedPort:             host.getProvisionedPort(nodePortP2PSeed),
	}
	net.seeds = append(net.seeds, seedNode)
	host.features = append(host.features, seedNode)

	return seedNode, nil
}
