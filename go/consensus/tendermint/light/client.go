package light

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/viper"
	"google.golang.org/grpc"

	tmlight "github.com/tendermint/tendermint/light"
	tmlightprovider "github.com/tendermint/tendermint/light/provider"
	tmlightdb "github.com/tendermint/tendermint/light/store/db"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"
	tmdb "github.com/tendermint/tm-db"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// ClientConfig is the configuration for the light client.
type ClientConfig struct {
	// GenesisDocument is the Tendermint genesis document.
	GenesisDocument *tmtypes.GenesisDoc

	// ConsensusNodes is a list of nodes exposing the Oasis Core public consensus services that are
	// used to fetch data required for syncing light clients. The first node is considered the
	// primary and at least two nodes must be specified.
	ConsensusNodes []node.TLSAddress

	// TrustOptions are Tendermint light client trust options.
	TrustOptions tmlight.TrustOptions
}

// lightClientProvider implements Tendermint's light client provider interface using the Oasis Core
// light client API.
type lightClientProvider struct {
	chainID string
	client  consensus.LightClientBackend
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ChainID() string {
	return lp.chainID
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) LightBlock(ctx context.Context, height int64) (*tmtypes.LightBlock, error) {
	lb, err := lp.client.GetLightBlock(ctx, height)
	switch {
	case err == nil:
	case errors.Is(err, consensus.ErrVersionNotFound):
		return nil, tmlightprovider.ErrLightBlockNotFound
	default:
		return nil, tmlightprovider.ErrNoResponse
	}

	// Decode Tendermint-specific light block.
	var protoLb tmproto.LightBlock
	if err = protoLb.Unmarshal(lb.Meta); err != nil {
		return nil, tmlightprovider.ErrBadLightBlock{Reason: err}
	}
	tlb, err := tmtypes.LightBlockFromProto(&protoLb)
	if err != nil {
		return nil, tmlightprovider.ErrBadLightBlock{Reason: err}
	}
	if err = tlb.ValidateBasic(lp.chainID); err != nil {
		return nil, tmlightprovider.ErrBadLightBlock{Reason: err}
	}

	return tlb, nil
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ReportEvidence(ctx context.Context, ev tmtypes.Evidence) error {
	proto, err := tmtypes.EvidenceToProto(ev)
	if err != nil {
		return fmt.Errorf("failed to convert evidence: %w", err)
	}
	meta, err := proto.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal evidence: %w", err)
	}

	return lp.client.SubmitEvidence(ctx, &consensus.Evidence{Meta: meta})
}

// newLightClientProvider creates a new provider for the Tendermint's light client.
//
// The provided chain ID must be the Tendermint chain ID.
func newLightClientProvider(
	chainID string,
	address node.TLSAddress,
) (tmlightprovider.Provider, error) {
	// Create TLS credentials.
	opts := cmnGrpc.ClientOptions{
		CommonName: identity.CommonName,
		ServerPubKeys: map[signature.PublicKey]bool{
			address.PubKey: true,
		},
	}
	creds, err := cmnGrpc.NewClientCreds(&opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS client credentials: %w", err)
	}

	conn, err := cmnGrpc.Dial(address.Address.String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("failed to dial public consensus service endpoint %s: %w", address, err)
	}

	return &lightClientProvider{
		chainID: chainID,
		client:  consensus.NewConsensusLightClient(conn),
	}, nil
}

type lightClient struct {
	// tmc is the Tendermint light client used for verifying headers.
	tmc *tmlight.Client
}

// Implements consensus.LightClientBackend.
func (lc *lightClient) GetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, error) {
	return lc.getPrimary().GetLightBlock(ctx, height)
}

// Implements consensus.LightClientBackend.
func (lc *lightClient) GetParameters(ctx context.Context, height int64) (*consensus.Parameters, error) {
	return lc.getPrimary().GetParameters(ctx, height)
}

// Implements consensus.LightClientBackend.
func (lc *lightClient) State() syncer.ReadSyncer {
	return lc.getPrimary().State()
}

// Implements consensus.LightClientBackend.
func (lc *lightClient) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return lc.getPrimary().SubmitTxNoWait(ctx, tx)
}

// Implements consensus.LightClientBackend.
func (lc *lightClient) SubmitEvidence(ctx context.Context, evidence *consensus.Evidence) error {
	return lc.getPrimary().SubmitEvidence(ctx, evidence)
}

// Implements Client.
func (lc *lightClient) GetVerifiedLightBlock(ctx context.Context, height int64) (*tmtypes.LightBlock, error) {
	return lc.tmc.VerifyLightBlockAtHeight(ctx, height, time.Now())
}

// Implements Client.
func (lc *lightClient) GetVerifiedParameters(ctx context.Context, height int64) (*tmproto.ConsensusParams, error) {
	p, err := lc.getPrimary().GetParameters(ctx, height)
	if err != nil {
		return nil, err
	}
	if p.Height <= 0 {
		return nil, fmt.Errorf("malformed height in response: %d", p.Height)
	}

	// Decode Tendermint-specific parameters.
	var protoParams tmproto.ConsensusParams
	if err = protoParams.Unmarshal(p.Meta); err != nil {
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}
	params := tmtypes.ConsensusParamsFromProto(protoParams)
	if err = params.ValidateConsensusParams(); err != nil {
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}

	// Fetch the header from the light client.
	l, err := lc.tmc.VerifyLightBlockAtHeight(ctx, p.Height, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch header %d from light client: %w", p.Height, err)
	}

	// Verify hash.
	if localHash := params.HashConsensusParams(); !bytes.Equal(localHash, l.ConsensusHash) {
		return nil, fmt.Errorf("mismatched parameters hash (expected: %X got: %X)",
			l.ConsensusHash,
			localHash,
		)
	}

	return &protoParams, nil
}

func (lc *lightClient) getPrimary() consensus.LightClientBackend {
	return lc.tmc.Primary().(*lightClientProvider).client
}

// NewClient creates a new light client.
func NewClient(ctx context.Context, cfg ClientConfig) (Client, error) {
	if numNodes := len(cfg.ConsensusNodes); numNodes < 2 {
		return nil, fmt.Errorf("at least two consensus nodes must be provided (got %d)", numNodes)
	}

	var providers []tmlightprovider.Provider
	for _, address := range cfg.ConsensusNodes {
		p, err := newLightClientProvider(cfg.GenesisDocument.ChainID, address)
		if err != nil {
			return nil, fmt.Errorf("failed to create light client provider: %w", err)
		}
		providers = append(providers, p)
	}

	tmc, err := tmlight.NewClient(
		ctx,
		cfg.GenesisDocument.ChainID,
		cfg.TrustOptions,
		providers[0],                   // Primary provider.
		providers[1:],                  // Witnesses.
		tmlightdb.New(tmdb.NewMemDB()), // TODO: Make the database configurable.
		tmlight.Logger(common.NewLogAdapter(!viper.GetBool(common.CfgLogDebug))),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	return &lightClient{
		tmc: tmc,
	}, nil
}
