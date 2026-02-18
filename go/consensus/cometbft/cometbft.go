package cometbft

import (
	"context"
	"encoding/hex"
	"fmt"

	cmtlight "github.com/cometbft/cometbft/light"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/full"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/stateless"
	"github.com/oasisprotocol/oasis-core/go/consensus/pricediscovery"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	p2pAPI "github.com/oasisprotocol/oasis-core/go/p2p/api"
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
	p2p p2pAPI.Service,
	metricsEnabled bool,
) (consensusAPI.Service, error) {
	genesisDoc, err := api.GetCometBFTGenesisDocument(doc)
	if err != nil {
		return nil, err
	}

	switch config.GlobalConfig.Mode {
	case config.ModeArchive:
		node, err := createArchiveNode(ctx, dataDir, identity, genesis, doc, genesisDoc, metricsEnabled)
		if err != nil {
			return nil, fmt.Errorf("failed to create archive node: %w", err)
		}
		return node, nil
	case config.ModeStatelessClient:
		node, err := createStatelessNode(ctx, dataDir, identity, genesis, doc, genesisDoc, p2p)
		if err != nil {
			return nil, fmt.Errorf("failed to create stateless node: %w", err)
		}
		return node, nil
	default:
		node, err := createFullNode(ctx, dataDir, identity, genesis, doc, genesisDoc, upgrader, p2p, metricsEnabled)
		if err != nil {
			return nil, fmt.Errorf("failed to create full node: %w", err)
		}
		return node, nil
	}
}

func createArchiveNode(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	genesis genesisAPI.Provider,
	doc *genesisAPI.Document,
	genesisDoc *cmttypes.GenesisDoc,
	metricsEnabled bool,
) (consensusAPI.Service, error) {
	cfg := full.ArchiveConfig{
		CommonConfig: createCommonConfig(dataDir, identity, genesis, doc, genesisDoc, metricsEnabled),
	}

	return full.NewArchive(ctx, cfg)
}

func createFullNode(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	genesis genesisAPI.Provider,
	doc *genesisAPI.Document,
	genesisDoc *cmttypes.GenesisDoc,
	upgrader upgradeAPI.Backend,
	p2p p2pAPI.Service,
	metricsEnabled bool,
) (consensusAPI.Service, error) {
	cfg := full.Config{
		CommonConfig:       createCommonConfig(dataDir, identity, genesis, doc, genesisDoc, metricsEnabled),
		TimeoutCommit:      doc.Consensus.Parameters.TimeoutCommit,
		EmptyBlockInterval: doc.Consensus.Parameters.EmptyBlockInterval,
		SkipTimeoutCommit:  doc.Consensus.Parameters.SkipTimeoutCommit,
		Upgrader:           upgrader,
	}

	return full.New(ctx, p2p, cfg)
}

func createStatelessNode(
	ctx context.Context,
	dataDir string,
	identity *identity.Identity,
	genesis genesisAPI.Provider,
	doc *genesisAPI.Document,
	genesisDoc *cmttypes.GenesisDoc,
	p2p p2pAPI.Service,
) (consensusAPI.Service, error) {
	provider, err := createProvider(identity)
	if err != nil {
		return nil, fmt.Errorf("failed to create provider: %w", err)
	}

	lightClient, err := createLightClient(ctx, dataDir, genesisDoc, doc, p2p)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	services, err := createStatelessServices(doc, genesis, genesisDoc, provider, lightClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create stateless client: %w", err)
	}

	submitter, err := createSubmissionManager(ctx, services)
	if err != nil {
		return nil, fmt.Errorf("failed to create submission manager: %w", err)
	}

	return stateless.NewService(services, submitter)
}

func createStatelessServices(
	doc *genesisAPI.Document,
	genesis genesisAPI.Provider,
	genesisDoc *cmttypes.GenesisDoc,
	provider consensusAPI.Backend,
	lightClient *light.Client,
) (*stateless.Services, error) {
	cfg := stateless.Config{
		ChainID:       doc.ChainID,
		ChainContext:  doc.ChainContext(),
		Genesis:       genesis,
		GenesisDoc:    genesisDoc,
		GenesisHeight: doc.Height,
		BaseEpoch:     doc.Beacon.Base,
		BaseHeight:    doc.Height,
	}

	return stateless.NewServices(provider, lightClient, cfg)
}

func createProvider(identity *identity.Identity) (consensusAPI.Backend, error) {
	addresses := config.GlobalConfig.Consensus.Providers
	if len(addresses) == 0 {
		return nil, fmt.Errorf("no providers configured")
	}
	providers := make([]consensusAPI.Backend, 0, len(addresses))
	for _, address := range addresses {
		provider, err := stateless.NewProvider(address, identity.TLSCertificate)
		if err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	return stateless.NewCompositeProvider(providers), nil
}

func createLightClient(
	ctx context.Context,
	dataDir string,
	genesisDoc *cmttypes.GenesisDoc,
	doc *genesisAPI.Document,
	p2p p2pAPI.Service,
) (*light.Client, error) {
	hash, err := hex.DecodeString(config.GlobalConfig.Consensus.LightClient.Trust.Hash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode trust hash: %w", err)
	}

	cfg := light.Config{
		GenesisDocument: genesisDoc,
		TrustOptions: cmtlight.TrustOptions{
			Period: config.GlobalConfig.Consensus.LightClient.Trust.Period,
			Height: int64(config.GlobalConfig.Consensus.LightClient.Trust.Height),
			Hash:   hash,
		},
		DataDir: dataDir,
	}

	return light.NewClient(ctx, doc.ChainContext(), p2p, cfg)
}

func createSubmissionManager(ctx context.Context, services consensusAPI.Services) (consensusAPI.SubmissionManager, error) {
	pd, err := pricediscovery.New(ctx, services.Core(), config.GlobalConfig.Consensus.Submission.GasPrice)
	if err != nil {
		return nil, fmt.Errorf("failed to create price discovery: %w", err)
	}

	return consensusAPI.NewSubmissionManager(services, pd, config.GlobalConfig.Consensus.Submission.MaxFee), nil
}

func createCommonConfig(
	dataDir string,
	identity *identity.Identity,
	genesis genesisAPI.Provider,
	doc *genesisAPI.Document,
	genesisDoc *cmttypes.GenesisDoc,
	metricsEnabled bool,
) full.CommonConfig {
	return full.CommonConfig{
		DataDir:            dataDir,
		Identity:           identity,
		ChainID:            doc.ChainID,
		ChainContext:       doc.ChainContext(),
		Genesis:            genesis,
		GenesisDoc:         genesisDoc,
		GenesisHeight:      doc.Height,
		BaseEpoch:          doc.Beacon.Base,
		BaseHeight:         doc.Height,
		PublicKeyBlacklist: doc.Consensus.Parameters.PublicKeyBlacklist,
		MetricsEnabled:     metricsEnabled,
	}
}

// NewLightService creates a new CometBFT light client service.
func NewLightService(
	ctx context.Context,
	doc *genesisAPI.Document,
	p2p rpc.P2P,
) (consensusAPI.LightService, error) {
	return light.New(ctx, doc.ChainContext(), p2p)
}
