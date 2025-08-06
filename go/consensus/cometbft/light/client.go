package light

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	cmtdb "github.com/cometbft/cometbft-db"
	cmtlight "github.com/cometbft/cometbft/light"
	cmtlightprovider "github.com/cometbft/cometbft/light/provider"
	cmtlightdb "github.com/cometbft/cometbft/light/store/db"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	cdb "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// dbName is the name of the database used to store trusted light blocks.
	dbName = "consensus/light"

	// storeHighWatermark is the maximum number of blocks the pruned store
	// can hold before triggering pruning.
	storeHighWatermark = 21_000

	// storeLowWatermark is the number of blocks to retain in the pruned store
	// after pruning is triggered.
	storeLowWatermark = 20_000
)

// Config is the configuration for the light client.
type Config struct {
	// GenesisDocument is the CometBFT genesis document.
	GenesisDocument *cmttypes.GenesisDoc

	// TrustOptions are CometBFT light client trust options.
	TrustOptions cmtlight.TrustOptions

	// DataDir is the node's data directory.
	//
	// If set, a persistent store is used to store trusted light blocks.
	// Otherwise, an in-memory store is used.
	DataDir string
}

// Client is a CometBFT consensus light client that talks with remote oasis-nodes that are using
// the CometBFT consensus backend and verifies responses.
type Client struct {
	mu sync.Mutex

	providers []*Provider

	// lightClient is a wrapped CometBFT light client used for verifying headers.
	lightClient *lazyClient
}

// NewClient creates a new light client.
func NewClient(ctx context.Context, chainContext string, p2p rpc.P2P, cfg Config) (*Client, error) {
	pool := NewProviderPool(ctx, chainContext, p2p)
	providers := make([]*Provider, 0, numWitnesses+1)
	for range numWitnesses + 1 {
		providers = append(providers, pool.NewProvider())
	}

	primary := providers[0]
	witnesses := make([]cmtlightprovider.Provider, 0, numWitnesses)
	for _, provider := range providers[1:] {
		witnesses = append(witnesses, provider)
	}

	var db cmtdb.DB
	switch cfg.DataDir {
	case "":
		db = cmtdb.NewMemDB()
	default:
		fn := filepath.Join(cfg.DataDir, dbName)
		cdb, err := cdb.New(fn, false)
		if err != nil {
			return nil, err
		}
		db = cmtdb.NewPrefixDB(cdb, []byte{})
	}
	store := cmtlightdb.New(db, "")
	store = newPrunedStore(store, storeHighWatermark, storeLowWatermark)

	lightClient, err := newLazyClient(
		cfg.GenesisDocument.ChainID,
		cfg.TrustOptions,
		primary,
		witnesses,
		store,
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

// LastTrustedHeight returns the last trusted height.
func (c *Client) LastTrustedHeight() (int64, error) {
	height, err := c.lightClient.LastTrustedHeight()
	if err != nil {
		return 0, err
	}
	if height == -1 {
		return 0, fmt.Errorf("no trusted headers")
	}
	return height, nil
}

// VerifyHeader verifies the given header.
func (c *Client) VerifyHeader(ctx context.Context, header *cmttypes.Header) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lightClient.VerifyHeader(ctx, header, time.Now())
}

// VerifyLightBlockAt returns a verified light block at the given height.
func (c *Client) VerifyLightBlockAt(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lightClient.VerifyLightBlockAtHeight(ctx, height, time.Now())
}

// VerifyParametersAt returns a verified consensus parameters at the given height.
func (c *Client) VerifyParametersAt(ctx context.Context, height int64) (*cmttypes.ConsensusParams, error) {
	params, pf, err := c.getParameters(ctx, height)
	if err != nil {
		return nil, err
	}
	if params.Height <= 0 {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("malformed height in response: %d", params.Height)
	}

	// Decode CometBFT-specific parameters.
	var proto cmtproto.ConsensusParams
	if err = proto.Unmarshal(params.Meta); err != nil {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}
	cmtparams := cmttypes.ConsensusParamsFromProto(proto)
	if err = cmtparams.ValidateBasic(); err != nil {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("malformed parameters: %w", err)
	}

	// Fetch the header from the light client.
	l, err := c.lightClient.VerifyLightBlockAtHeight(ctx, params.Height, time.Now())
	if err != nil {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("failed to fetch header %d from light client: %w", params.Height, err)
	}

	// Verify hash.
	if hash := cmtparams.Hash(); !bytes.Equal(hash, l.ConsensusHash) {
		pf.RecordBadPeer()
		return nil, fmt.Errorf("mismatched parameters hash (expected: %X got: %X)",
			l.ConsensusHash,
			hash,
		)
	}

	return &cmtparams, nil
}

func (c *Client) getParameters(ctx context.Context, height int64) (*consensus.Parameters, rpc.PeerFeedback, error) {
	return tryProviders(ctx, c.providers, func(p *Provider) (*consensus.Parameters, rpc.PeerFeedback, error) {
		return p.GetParameters(ctx, height)
	})
}

func tryProviders[R any](
	ctx context.Context,
	providers []*Provider,
	fn func(*Provider) (R, rpc.PeerFeedback, error),
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
