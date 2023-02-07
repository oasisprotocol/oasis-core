package tendermint

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/full"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/light"
	lightAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/light/api"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	upgradeAPI "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// New creates a new Tendermint consensus backend.
func New(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	upgrader upgradeAPI.Backend,
	genesisProvider genesisAPI.Provider,
) (consensusAPI.Backend, error) {
	switch config.GlobalConfig.Mode {
	case config.ModeArchive:
		// Archive node.
		return full.NewArchive(ctx, dataDir, identity, genesisProvider)
	default:
		// Full node.
		return full.New(ctx, dataDir, identity, upgrader, genesisProvider)
	}
}

// NewLightClient creates a new Tendermint light client service.
func NewLightClient(ctx context.Context, dataDir string, genesis *genesisAPI.Document, consensus consensusAPI.Backend, p2p rpc.P2P) (lightAPI.ClientService, error) {
	return light.New(ctx, dataDir, genesis, consensus, p2p)
}
