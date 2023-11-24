package light

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
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
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light/api"
	p2pLight "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light/p2p"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

type lightClient struct {
	// tmc is the CometBFT light client used for verifying headers.
	tmc *cmtlight.Client
}

func tryProviders[R any](
	ctx context.Context,
	lc *lightClient,
	fn func(api.Provider) (R, rpc.PeerFeedback, error),
) (R, rpc.PeerFeedback, error) {
	// Primary provider.
	providers := append([]api.Provider{}, lc.tmc.Primary().(api.Provider))
	// Additional providers.
	for _, provider := range lc.tmc.Witnesses() {
		providers = append(providers, provider.(api.Provider))
	}

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

// GetStoredBlock implements api.Client.
func (lc *lightClient) GetStoredLightBlock(height int64) (*consensus.LightBlock, error) {
	clb, err := lc.tmc.TrustedLightBlock(height)
	if err != nil {
		return nil, err
	}
	return api.NewLightBlock(clb)
}

// GetLightBlock implements api.Client.
func (lc *lightClient) GetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, rpc.PeerFeedback, error) {
	return tryProviders(ctx, lc, func(p api.Provider) (*consensus.LightBlock, rpc.PeerFeedback, error) {
		return p.GetLightBlock(ctx, height)
	})
}

// GetParameters implements api.Client.
func (lc *lightClient) GetParameters(ctx context.Context, height int64) (*consensus.Parameters, rpc.PeerFeedback, error) {
	return tryProviders(ctx, lc, func(p api.Provider) (*consensus.Parameters, rpc.PeerFeedback, error) {
		return p.GetParameters(ctx, height)
	})
}

// SubmitEvidence implements api.Client.
func (lc *lightClient) SubmitEvidence(ctx context.Context, evidence *consensus.Evidence) (rpc.PeerFeedback, error) {
	_, pf, err := tryProviders(ctx, lc, func(p api.Provider) (any, rpc.PeerFeedback, error) {
		pf, err := p.SubmitEvidence(ctx, evidence)
		return nil, pf, err
	})
	return pf, err
}

// GetVerifiedLightBlock implements Client.
func (lc *lightClient) GetVerifiedLightBlock(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	return lc.tmc.VerifyLightBlockAtHeight(ctx, height, time.Now())
}

// GetVerifiedLightBlock implements Client.
func (lc *lightClient) GetVerifiedParameters(ctx context.Context, height int64) (*cmtproto.ConsensusParams, error) {
	p, pf, err := lc.GetParameters(ctx, height)
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
	l, err := lc.tmc.VerifyLightBlockAtHeight(ctx, p.Height, time.Now())
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

// NewInternalClient creates an internal and non-persistent light client.
//
// This client is instantiated from the provided (obtained out of bound) trusted block
// and is used internally for CometBFT's state sync protocol.
func NewInternalClient(ctx context.Context, chainContext string, p2p rpc.P2P, cfg api.ClientConfig) (api.Client, error) {
	pool := p2pLight.NewLightClientProviderPool(ctx, chainContext, cfg.GenesisDocument.ChainID, p2p)

	initChCases := []reflect.SelectCase{}
	var providers []cmtlightprovider.Provider
	for i := 0; i < numProviders; i++ {
		p := pool.NewLightClientProvider()

		providers = append(providers, p)
		initChCases = append(initChCases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(p.Initialized()),
		})
	}
	// LightClient instantiation immediately starts the light client and fails if no providers
	// are available, ensure at least one provider has been initialized.
	idx, _, _ := reflect.Select(initChCases)

	// Make the initialized provider the primary.
	primary := providers[idx]
	providers[idx] = providers[len(providers)-1]
	providers = providers[:len(providers)-1]

	tmc, err := cmtlight.NewClient(
		ctx,
		cfg.GenesisDocument.ChainID,
		cfg.TrustOptions,
		primary,   // Primary provider.
		providers, // Witnesses.
		cmtlightdb.New(dbm.NewMemDB(), ""),
		cmtlight.MaxRetryAttempts(5), // TODO: Make this configurable.
		cmtlight.Logger(common.NewLogAdapter(!config.GlobalConfig.Consensus.LogDebug)),
		cmtlight.DisableProviderRemoval(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create light client: %w", err)
	}

	return &lightClient{
		tmc: tmc,
	}, nil
}
