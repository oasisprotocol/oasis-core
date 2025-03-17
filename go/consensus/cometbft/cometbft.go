package cometbft

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/full"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light"
	lightAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light/api"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// New creates a new CometBFT consensus backend.
func New(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	upgrader upgradeAPI.Backend,
	genesisDoc *genesisAPI.Document,
) (consensusAPI.Backend, error) {
	switch config.GlobalConfig.Mode {
	case config.ModeArchive:
		// Archive node.
		return full.NewArchive(ctx, dataDir, identity, genesisDoc)
	default:
		// Full node.
		return full.New(ctx, dataDir, identity, upgrader, genesisDoc)
	}
}

// NewLightClient creates a new CometBFT light client service.
func NewLightClient(
	ctx context.Context,
	dataDir string,
	genesis *genesisAPI.Document,
	consensus consensusAPI.Backend,
	p2p rpc.P2P,
) (lightAPI.ClientService, error) {
	return light.New(ctx, dataDir, genesis, consensus, p2p)
}
