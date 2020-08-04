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
	ctx context.Context // XXX: Hack needed because tmlightprovider.Provider doesn't pass contexts.

	chainID string
	client  consensus.LightClientBackend
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ChainID() string {
	return lp.chainID
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) SignedHeader(height int64) (*tmtypes.SignedHeader, error) {
	shdr, err := lp.client.GetSignedHeader(lp.ctx, height)
	switch {
	case err == nil:
	case errors.Is(err, consensus.ErrVersionNotFound):
		return nil, tmlightprovider.ErrSignedHeaderNotFound
	default:
		return nil, fmt.Errorf("failed to fetch signed header: %w", err)
	}

	// Decode Tendermint-specific signed header.
	var protoSigHdr tmproto.SignedHeader
	if err = protoSigHdr.Unmarshal(shdr.Meta); err != nil {
		return nil, fmt.Errorf("received malformed header: %w", err)
	}
	sh, err := tmtypes.SignedHeaderFromProto(&protoSigHdr)
	if err != nil {
		return nil, fmt.Errorf("received malformed header: %w", err)
	}

	if lp.chainID != sh.ChainID {
		return nil, fmt.Errorf("incorrect chain ID (expected: %s got: %s)",
			lp.chainID,
			sh.ChainID,
		)
	}

	return sh, nil
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ValidatorSet(height int64) (*tmtypes.ValidatorSet, error) {
	vs, err := lp.client.GetValidatorSet(lp.ctx, height)
	switch {
	case err == nil:
	case errors.Is(err, consensus.ErrVersionNotFound):
		return nil, tmlightprovider.ErrValidatorSetNotFound
	default:
		return nil, fmt.Errorf("failed to fetch validator set: %w", err)
	}

	// Decode Tendermint-specific validator set.
	var protoVals tmproto.ValidatorSet
	if err = protoVals.Unmarshal(vs.Meta); err != nil {
		return nil, fmt.Errorf("received malformed validator set: %w", err)
	}
	vals, err := tmtypes.ValidatorSetFromProto(&protoVals)
	if err != nil {
		return nil, fmt.Errorf("received malformed validator set: %w", err)
	}

	return vals, nil
}

// Implements tmlightprovider.Provider.
func (lp *lightClientProvider) ReportEvidence(ev tmtypes.Evidence) error {
	// TODO: Implement SubmitEvidence.
	return fmt.Errorf("not yet implemented")
}

// newLightClientProvider creates a new provider for the Tendermint's light client.
//
// The provided chain ID must be the Tendermint chain ID.
func newLightClientProvider(
	ctx context.Context,
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
		ctx:     ctx,
		chainID: chainID,
		client:  consensus.NewConsensusLightClient(conn),
	}, nil
}

type lightClient struct {
	// tmc is the Tendermint light client used for verifying headers.
	tmc *tmlight.Client
}

// Implements consensus.LightClientBackend.
func (lc *lightClient) GetSignedHeader(ctx context.Context, height int64) (*consensus.SignedHeader, error) {
	return lc.getPrimary().GetSignedHeader(ctx, height)
}

// Implements consensus.LightClientBackend.
func (lc *lightClient) GetValidatorSet(ctx context.Context, height int64) (*consensus.ValidatorSet, error) {
	return lc.getPrimary().GetValidatorSet(ctx, height)
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

// Implements Client.
func (lc *lightClient) GetVerifiedSignedHeader(ctx context.Context, height int64) (*tmtypes.SignedHeader, error) {
	return lc.tmc.VerifyHeaderAtHeight(height, time.Now())
}

func (lc *lightClient) GetVerifiedValidatorSet(ctx context.Context, height int64) (*tmtypes.ValidatorSet, int64, error) {
	return lc.tmc.TrustedValidatorSet(height)
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
	var params tmproto.ConsensusParams
	if err = params.Unmarshal(p.Meta); err != nil {
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}
	if err = tmtypes.ValidateConsensusParams(params); err != nil {
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}

	// Fetch the header from the light client.
	h, err := lc.tmc.VerifyHeaderAtHeight(p.Height, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch header %d from light client: %w", p.Height, err)
	}

	// Verify hash.
	if localHash := tmtypes.HashConsensusParams(params); !bytes.Equal(localHash, h.ConsensusHash) {
		return nil, fmt.Errorf("mismatched parameters hash (expected: %X got: %X)",
			h.ConsensusHash,
			localHash,
		)
	}

	return &params, nil
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
		p, err := newLightClientProvider(ctx, cfg.GenesisDocument.ChainID, address)
		if err != nil {
			return nil, fmt.Errorf("failed to create light client provider: %w", err)
		}
		providers = append(providers, p)
	}

	tmc, err := tmlight.NewClient(
		cfg.GenesisDocument.ChainID,
		cfg.TrustOptions,
		providers[0],                       // Primary provider.
		providers[1:],                      // Witnesses.
		tmlightdb.New(tmdb.NewMemDB(), ""), // TODO: Make the database configurable.
		tmlight.MaxRetryAttempts(5),        // TODO: Make this configurable.
		tmlight.Logger(common.NewLogAdapter(!viper.GetBool(common.CfgLogDebug))),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	return &lightClient{
		tmc: tmc,
	}, nil
}
