package light

import (
	"bytes"
	"context"
	"fmt"
	"time"

	dbm "github.com/cometbft/cometbft-db"
	cmtlight "github.com/cometbft/cometbft/light"
	cmtlightprovider "github.com/cometbft/cometbft/light/provider"
	cmtlightdb "github.com/cometbft/cometbft/light/store/db"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	p2pLight "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light/p2p"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

// Config is the configuration for the light client.
type Config struct {
	// GenesisDocument is the CometBFT genesis document.
	GenesisDocument *cmttypes.GenesisDoc

	// TrustOptions are CometBFT light client trust options.
	TrustOptions cmtlight.TrustOptions
}

// Client is a CometBFT consensus light client that talks with remote oasis-nodes that are using
// the CometBFT consensus backend and verifies responses.
type Client struct {
	providers []*p2pLight.LightClientProvider

	// lightClient is a wrapped CometBFT light client used for verifying headers.
	lightClient *lazyClient
}

func tryProviders[R any](
	ctx context.Context,
	providers []*p2pLight.LightClientProvider,
	fn func(*p2pLight.LightClientProvider) (R, rpc.PeerFeedback, error),
) (R, rpc.PeerFeedback, error) {
	var (
		result R
		err    error
	)
	for _, provider := range providers {
		if ctx.Err() != nil {
			return result, nil, ctx.Err()
		}

		var pf rpc.PeerFeedback
		result, pf, err = fn(provider)
		if err == nil {
			return result, pf, nil
		}
	}

	// Trigger primary provider refresh if everything fails.
	providers[0].RefreshPeer()

	return result, nil, err
}

// GetLightBlock queries peers for a specific light block.
func (c *Client) GetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, rpc.PeerFeedback, error) {
	return tryProviders(ctx, c.providers, func(p *p2pLight.LightClientProvider) (*consensus.LightBlock, rpc.PeerFeedback, error) {
		return p.GetLightBlock(ctx, height)
	})
}

// GetParameters queries peers for consensus parameters for a specific height.
func (c *Client) GetParameters(ctx context.Context, height int64) (*consensus.Parameters, rpc.PeerFeedback, error) {
	return tryProviders(ctx, c.providers, func(p *p2pLight.LightClientProvider) (*consensus.Parameters, rpc.PeerFeedback, error) {
		return p.GetParameters(ctx, height)
	})
}

// GetVerifiedLightBlock returns a verified light block.
func (c *Client) GetVerifiedLightBlock(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	return c.lightClient.VerifyLightBlockAtHeight(ctx, height, time.Now())
}

// GetVerifiedParameters returns verified consensus parameters.
func (c *Client) GetVerifiedParameters(ctx context.Context, height int64) (*cmtproto.ConsensusParams, error) {
	p, pf, err := c.GetParameters(ctx, height)
	if err != nil {
		return nil, err
	}
	if p.Height <= 0 {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("malformed height in response: %d", p.Height)
	}

	// Decode CometBFT-specific parameters.
	var paramsPB cmtproto.ConsensusParams
	if err = paramsPB.Unmarshal(p.Meta); err != nil {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}
	params := cmttypes.ConsensusParamsFromProto(paramsPB)
	if err = params.ValidateBasic(); err != nil {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}

	// Fetch the header from the light client.
	l, err := c.lightClient.VerifyLightBlockAtHeight(ctx, p.Height, time.Now())
	if err != nil {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("failed to fetch header %d from light client: %w", p.Height, err)
	}

	// Verify hash.
	if localHash := params.Hash(); !bytes.Equal(localHash, l.ConsensusHash) {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("mismatched parameters hash (expected: %X got: %X)",
			l.ConsensusHash,
			localHash,
		)
	}

	return &paramsPB, nil
}

// NewClient creates an internal and non-persistent light client.
//
// This client is instantiated from the provided (obtained out of bound) trusted block
// and is used internally for CometBFT's state sync protocol.
func NewClient(ctx context.Context, chainContext string, p2p rpc.P2P, cfg Config) (*Client, error) {
	pool := p2pLight.NewLightClientProviderPool(ctx, chainContext, p2p)
	providers := make([]*p2pLight.LightClientProvider, 0, numWitnesses+1)
	for range numWitnesses + 1 {
		providers = append(providers, pool.NewLightClientProvider())
	}

	primary := providers[0]
	witnesses := make([]cmtlightprovider.Provider, 0, numWitnesses)
	for _, provider := range providers[1:] {
		witnesses = append(witnesses, provider)
	}

	lightClient, err := newLazyClient(
		cfg.GenesisDocument.ChainID,
		cfg.TrustOptions,
		primary,
		witnesses,
		cmtlightdb.New(dbm.NewMemDB(), ""),
		cmtlight.MaxRetryAttempts(lcMaxRetryAttempts), // TODO: Make this configurable.
		cmtlight.Logger(common.NewLogAdapter(!config.GlobalConfig.Consensus.LogDebug)),
		cmtlight.DisableProviderRemoval(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	return &Client{
		providers:   providers,
		lightClient: lightClient,
	}, nil
}
