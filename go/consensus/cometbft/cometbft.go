package cometbft

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/full"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light"
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
	genesis genesisAPI.Provider,
	doc *genesisAPI.Document,
) (consensusAPI.Backend, error) {
	genesisDoc, err := api.GetCometBFTGenesisDocument(doc)
	if err != nil {
		return nil, err
	}

	commonCfg := full.CommonConfig{
		DataDir:            dataDir,
		Identity:           identity,
		ChainID:            doc.ChainID,
		ChainContext:       doc.ChainContext(),
		Genesis:            genesis,
		GenesisDoc:         genesisDoc,
		GenesisHeight:      doc.Height,
		PublicKeyBlacklist: doc.Consensus.Parameters.PublicKeyBlacklist,
	}

	switch config.GlobalConfig.Mode {
	case config.ModeArchive:
		cfg := full.ArchiveConfig{
			CommonConfig: commonCfg,
		}
		return full.NewArchive(ctx, cfg)
	default:
		cfg := full.Config{
			CommonConfig:       commonCfg,
			TimeoutCommit:      doc.Consensus.Parameters.TimeoutCommit,
			EmptyBlockInterval: doc.Consensus.Parameters.EmptyBlockInterval,
			SkipTimeoutCommit:  doc.Consensus.Parameters.SkipTimeoutCommit,
			Upgrader:           upgrader,
		}
		return full.New(ctx, cfg)
	}
}

// NewLightService creates a new CometBFT light client service.
func NewLightService(
	ctx context.Context,
	dataDir string,
	consensus consensusAPI.Backend,
	p2p rpc.P2P,
) (consensusAPI.LightService, error) {
	return light.New(ctx, dataDir, consensus, p2p)
}
