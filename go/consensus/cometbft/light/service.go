// Package light implements a CometBFT light client service.
package light

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"

	dbm "github.com/cometbft/cometbft-db"
	cmtlight "github.com/cometbft/cometbft/light"
	cmtlightprovider "github.com/cometbft/cometbft/light/provider"
	cmtlightstore "github.com/cometbft/cometbft/light/store"
	cmtlightdb "github.com/cometbft/cometbft/light/store/db"
	cmtproto "github.com/cometbft/cometbft/proto/tendermint/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/config"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmtAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/common"
	cmtConfig "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/config"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/db"
	"github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light/api"
	p2pLight "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/light/p2p"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	dbName = "consensus/light"

	// numProviders is the number of libp2p backed CometBFT light-block providers to be instantiated.
	numProviders = 3
	// lcMaxRetryAttempts is the number of retry attempts the CometBFT light client does,
	// before switching the primary provider.
	lcMaxRetryAttempts = 5
)

type client struct {
	ctx context.Context

	enabled bool

	logger *logging.Logger

	genesis   *genesisAPI.Document
	consensus consensus.Backend
	p2p       rpc.P2P

	store cmtlightstore.Store

	lc        *lightClient
	providers []api.Provider

	initOnce sync.Once
	initCh   chan struct{} // closed internally when initialized
	stopCh   chan struct{} // closed internally to trigger stop
	stopOnce sync.Once
	quitCh   chan struct{} // closed after stopped
}

// Name implements api.ClientService
func (*client) Name() string {
	return "cometbft/light"
}

func (c *client) Start() error {
	go c.worker()

	return nil
}

func (c *client) GetStatus() (*consensus.LightClientStatus, error) {
	status := &consensus.LightClientStatus{}
	oldest, err := c.store.FirstLightBlockHeight()
	if err != nil {
		return nil, err
	}
	status.OldestHeight = oldest
	if oldest > -1 { // -1 indicates empty store.
		var lb *cmttypes.LightBlock
		lb, err = c.store.LightBlock(oldest)
		if err != nil {
			return nil, err
		}
		status.OldestHash = hash.LoadFromHexBytes(lb.Header.Hash())
		status.OldestTime = lb.Time
	}

	latest, err := c.store.LastLightBlockHeight()
	if err != nil {
		return nil, err
	}
	status.LatestHeight = latest
	if latest > -1 { // -1 indicates empty store.
		var lb *cmttypes.LightBlock
		lb, err := c.store.LightBlock(latest)
		if err != nil {
			return nil, err
		}
		status.LatestHash = hash.LoadFromHexBytes(lb.Header.Hash())
		status.LatestTime = lb.Time
	}

	for _, p := range c.providers {
		if id := p.PeerID(); id != "" {
			status.PeerIDs = append(status.PeerIDs, id)
		}
	}

	return status, nil
}

func (c *client) Stop() {
	c.stopOnce.Do(func() { close(c.stopCh) })
}

func (c *client) Quit() <-chan struct{} {
	return c.quitCh
}

func (c *client) Cleanup() {
}

func (c *client) worker() {
	if !c.enabled {
		// In case the worker is not enabled, close the init channel immediately.
		close(c.initCh)
		return
	}
	defer func() {
		c.initOnce.Do(func() { close(c.initCh) })
		close(c.quitCh)
	}()

	// Wait for consensus to be synced.
	select {
	case <-c.stopCh:
		return
	case <-c.ctx.Done():
		return
	case <-c.consensus.Synced():
	}

	chainCtx, err := c.consensus.GetChainContext(c.ctx)
	if err != nil {
		c.logger.Error("failed to obtain chain context", "err", err)
		return
	}
	tmChainID := cmtAPI.CometBFTChainID(chainCtx)

	// Loads the local block at the provided height and adds it to the trust store.
	trustLocalBlock := func(ctx context.Context, height int64) error {
		var lb *consensus.LightBlock
		if lb, err = c.consensus.GetLightBlock(ctx, height); err != nil {
			return fmt.Errorf("failed to obtain block %d from consensus: %w", height, err)
		}
		// Convert to protobuff LightBlock.
		var pb cmtproto.LightBlock
		if err = pb.Unmarshal(lb.Meta); err != nil {
			return fmt.Errorf("failed to unmarshal cometbft protobuff light block: %w", err)
		}
		// Convert to CometBFT LightBlock.
		var tmLb *cmttypes.LightBlock
		if tmLb, err = cmttypes.LightBlockFromProto(&pb); err != nil {
			return fmt.Errorf("failed to convert protobuff light block into cometbft light block: %w", err)
		}
		if err = tmLb.ValidateBasic(tmChainID); err != nil {
			return fmt.Errorf("local light block %d seems to be invalid (data corruption?): %w", height, err)
		}
		if err = c.store.SaveLightBlock(tmLb); err != nil {
			return fmt.Errorf("failed to save block %d into the light client trust store: %w", lb.Height, err)
		}
		return nil
	}

	// Store earliest block into trust store.
	lastRetainedHeight, err := c.consensus.(cmtAPI.Backend).GetLastRetainedVersion(c.ctx)
	if err != nil {
		c.logger.Error("failed to get last retained height from consensus", "err", err)
		return
	}
	// Some pruning configurations return 0 instead of a valid block height. Clamp those to the
	// genesis height.
	if lastRetainedHeight < c.genesis.Height {
		lastRetainedHeight = c.genesis.Height
	}
	if err = trustLocalBlock(c.ctx, lastRetainedHeight); err != nil {
		c.logger.Error("failed to store last retained block into trust store", "err", err)
		// Errors ignored as we could still initialize if we can get the latest block. If not, the
		// light client constructor will fail anyway.
	}

	// Store latest block into trust store.
	if err = trustLocalBlock(c.ctx, consensus.HeightLatest); err != nil {
		c.logger.Error("failed to store last retained block into trust store", "err", err)
	}

	// Initialize a provider pool.
	pool := p2pLight.NewLightClientProviderPool(c.ctx, chainCtx, tmChainID, c.p2p)
	var providers []cmtlightprovider.Provider
	for i := 0; i < numProviders; i++ {
		p := pool.NewLightClientProvider()
		providers = append(providers, p)
		c.providers = append(c.providers, p)
	}

	opts := []cmtlight.Option{
		cmtlight.MaxRetryAttempts(lcMaxRetryAttempts),
		cmtlight.Logger(common.NewLogAdapter(!config.GlobalConfig.Consensus.LogDebug)),
		cmtlight.DisableProviderRemoval(),
	}
	switch config.GlobalConfig.Consensus.Prune.Strategy {
	case cmtConfig.PruneStrategyNone:
		opts = append(opts, cmtlight.PruningSize(0)) // Disable pruning the light store.
	default:
		opts = append(opts, cmtlight.PruningSize(config.GlobalConfig.Consensus.Prune.NumLightBlocksKept))
	}

	tmc, err := cmtlight.NewClientFromTrustedStore(
		tmChainID,
		config.GlobalConfig.Consensus.StateSync.TrustPeriod,
		providers[0],  // Primary provider.
		providers[1:], // Witnesses.
		c.store,
		opts...,
	)
	if err != nil {
		c.logger.Error("failed to initialize cometbft light client", "err", err)
		return
	}
	c.lc = &lightClient{tmc: tmc}
	c.initOnce.Do(func() { close(c.initCh) })

	// Watch epochs and insert new trusted blocks on every epoch transition.
	ch, sub, err := c.consensus.Beacon().WatchEpochs(c.ctx)
	if err != nil {
		c.logger.Error("failed to watch epochs", "err", err)
		return
	}
	defer sub.Close()
	for {
		select {
		case <-c.stopCh:
			return
		case <-c.ctx.Done():
			return
		case <-ch:
			if err = trustLocalBlock(c.ctx, consensus.HeightLatest); err != nil {
				c.logger.Error("failed to store light block into trust store", "err", err)
				continue
			}
		}
	}
}

// GetStoredLightBlock implements api.Client.
func (c *client) GetStoredLightBlock(height int64) (*consensus.LightBlock, error) {
	clb, err := c.store.LightBlock(height)
	if err != nil {
		return nil, err
	}
	return api.NewLightBlock(clb)
}

// GetLightBlock implements api.Client.
func (c *client) GetLightBlock(ctx context.Context, height int64) (*consensus.LightBlock, rpc.PeerFeedback, error) {
	select {
	case <-c.initCh:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	// Local backend source.
	localBackendSource := func() (*consensus.LightBlock, rpc.PeerFeedback, error) {
		lb, err := c.consensus.GetLightBlock(ctx, height)
		if err != nil {
			c.logger.Debug("failed to fetch light block from local full node",
				"err", err,
				"height", height,
			)
			return nil, nil, err
		}

		return lb, rpc.NewNopPeerFeedback(), nil
	}

	// Light client store.
	lightClientStoreSource := func() (*consensus.LightBlock, rpc.PeerFeedback, error) {
		lb, err := c.GetStoredLightBlock(height)
		if err != nil {
			c.logger.Debug("failed to fetch light block from light client store",
				"err", err,
				"height", height,
			)
			return nil, nil, err
		}

		return lb, rpc.NewNopPeerFeedback(), nil
	}

	// Direct peer query.
	directPeerQuerySource := func() (*consensus.LightBlock, rpc.PeerFeedback, error) {
		return c.lc.GetLightBlock(ctx, height)
	}

	// Try all sources in order.
	var mergedErr error
	for _, src := range []func() (*consensus.LightBlock, rpc.PeerFeedback, error){
		localBackendSource,
		lightClientStoreSource,
		directPeerQuerySource,
	} {
		lb, pf, err := src()
		if err == nil {
			return lb, pf, nil
		}

		mergedErr = errors.Join(mergedErr, err)
	}

	return nil, nil, mergedErr
}

// GetParameters implements api.Client.
func (c *client) GetParameters(ctx context.Context, height int64) (*consensus.Parameters, rpc.PeerFeedback, error) {
	select {
	case <-c.initCh:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}

	// Try local backend first.
	p, err := c.consensus.GetParameters(ctx, height)
	if err == nil {
		return p, rpc.NewNopPeerFeedback(), nil
	}
	c.logger.Debug("failed to fetch parameters from local full node", "err", err)

	return c.lc.GetParameters(ctx, height)
}

// SubmitEvidence implements api.Client.
func (c *client) SubmitEvidence(ctx context.Context, evidence *consensus.Evidence) (rpc.PeerFeedback, error) {
	select {
	case <-c.initCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return c.lc.SubmitEvidence(ctx, evidence)
}

// GetVerifiedLightBlock implements Client.
func (c *client) GetVerifiedLightBlock(ctx context.Context, height int64) (*cmttypes.LightBlock, error) {
	select {
	case <-c.initCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return c.lc.GetVerifiedLightBlock(ctx, height)
}

// GetVerifiedParameters implements Client.
func (c *client) GetVerifiedParameters(ctx context.Context, height int64) (*cmtproto.ConsensusParams, error) {
	select {
	case <-c.initCh:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	return c.lc.GetVerifiedParameters(ctx, height)
}

// New creates a new CometBFT light client service backed by the local full node.
//
// This light client is initialized with a trusted blocks obtained from the local consensus backend.
func New(ctx context.Context, dataDir string, genesis *genesisAPI.Document, c consensus.Backend, p2p rpc.P2P) (api.ClientService, error) {
	tdb, err := db.New(filepath.Join(dataDir, dbName), false)
	if err != nil {
		return nil, err
	}
	store := cmtlightdb.New(dbm.NewPrefixDB(tdb, []byte{}), "")

	return &client{
		ctx:       ctx,
		enabled:   c.SupportedFeatures().Has(consensus.FeatureFullNode),
		logger:    logging.GetLogger("consensus/cometbft/light"),
		genesis:   genesis,
		consensus: c,
		p2p:       p2p,
		store:     store,
		initCh:    make(chan struct{}),
		stopCh:    make(chan struct{}),
		quitCh:    make(chan struct{}),
	}, nil
}
