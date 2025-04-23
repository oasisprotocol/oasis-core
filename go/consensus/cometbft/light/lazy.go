package light

import (
	"context"
	"fmt"
	"time"

	cmtlight "github.com/cometbft/cometbft/light"
	cmtlightprovider "github.com/cometbft/cometbft/light/provider"
	cmtlightstore "github.com/cometbft/cometbft/light/store"
	cmttypes "github.com/cometbft/cometbft/types"

	cmSync "github.com/oasisprotocol/oasis-core/go/common/sync"
)

// lazyClient wraps a CometBFT light client with lazy initialization.
//
// It defers the creation of the underlying client until it's actually needed,
// ensuring successful initialization even when no blocks are initially
// available from the primary provider.
type lazyClient struct {
	chainID      string
	trustOptions cmtlight.TrustOptions
	primary      cmtlightprovider.Provider
	witnesses    []cmtlightprovider.Provider
	trustedStore cmtlightstore.Store
	options      []cmtlight.Option

	// The light client is lazily initialized and should be used with care.
	// Only access it after confirming that it has already been initialized
	// or after successful initialization.
	initOnce    cmSync.FallibleOnce
	lightClient *cmtlight.Client
}

// newLazyClient creates a new lazy light client.
func newLazyClient(
	chainID string,
	trustOptions cmtlight.TrustOptions,
	primary cmtlightprovider.Provider,
	witnesses []cmtlightprovider.Provider,
	trustedStore cmtlightstore.Store,
	options ...cmtlight.Option,
) (*lazyClient, error) {
	if len(witnesses) == 0 {
		return nil, fmt.Errorf("no witnesses")
	}

	providers := append([]cmtlightprovider.Provider{primary}, witnesses...)
	for _, p := range providers {
		if p.ChainID() != chainID {
			return nil, fmt.Errorf("invalid chain ID: %s", p.ChainID())
		}
	}

	if err := trustOptions.ValidateBasic(); err != nil {
		return nil, fmt.Errorf("invalid trust options: %w", err)
	}

	return &lazyClient{
		chainID:      chainID,
		trustOptions: trustOptions,
		primary:      primary,
		witnesses:    witnesses,
		trustedStore: trustedStore,
		options:      options,
	}, nil
}

// ChainID returns the chain ID the light client was configured with.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) ChainID() string {
	return c.chainID
}

// Primary returns the primary provider.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) Primary() cmtlightprovider.Provider {
	if !c.initialized() {
		return c.primary
	}
	return c.lightClient.Primary()
}

// Witnesses returns the witness providers.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) Witnesses() []cmtlightprovider.Provider {
	if !c.initialized() {
		return c.witnesses
	}
	return c.lightClient.Witnesses()
}

// Cleanup removes all the data (headers and validator sets) stored.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) Cleanup() error {
	if !c.initialized() {
		return nil
	}
	return c.lightClient.Cleanup()
}

// FirstTrustedHeight returns a first trusted height.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) FirstTrustedHeight() (int64, error) {
	if !c.initialized() {
		return -1, nil
	}
	return c.lightClient.FirstTrustedHeight()
}

// LastTrustedHeight returns a last trusted height.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) LastTrustedHeight() (int64, error) {
	if !c.initialized() {
		return -1, nil
	}
	return c.lightClient.LastTrustedHeight()
}

// TrustedLightBlock returns a trusted light block at the given height.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) TrustedLightBlock(height int64) (*cmttypes.LightBlock, error) {
	if !c.initialized() {
		return nil, cmtlightstore.ErrLightBlockNotFound
	}
	return c.lightClient.TrustedLightBlock(height)
}

// Update attempts to advance the state by downloading the latest light
// block and verifying it.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) Update(ctx context.Context, now time.Time) (*cmttypes.LightBlock, error) {
	if err := c.initialize(ctx); err != nil {
		return nil, err
	}
	return c.lightClient.Update(ctx, now)
}

// VerifyHeader verifies a new header against the trusted state.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) VerifyHeader(ctx context.Context, newHeader *cmttypes.Header, now time.Time) error {
	if err := c.initialize(ctx); err != nil {
		return err
	}
	return c.lightClient.VerifyHeader(ctx, newHeader, now)
}

// VerifyLightBlockAtHeight fetches the light block at the given height
// and verifies it.
//
// For details, see the CometBFT light client documentation.
func (c *lazyClient) VerifyLightBlockAtHeight(ctx context.Context, height int64, now time.Time) (*cmttypes.LightBlock, error) {
	if err := c.initialize(ctx); err != nil {
		return nil, err
	}
	return c.lightClient.VerifyLightBlockAtHeight(ctx, height, now)
}

func (c *lazyClient) initialized() bool {
	return c.initOnce.Done()
}

func (c *lazyClient) initialize(ctx context.Context) error {
	return c.initOnce.Do(func() error {
		lightClient, err := cmtlight.NewClient(
			ctx,
			c.chainID,
			c.trustOptions,
			c.primary,
			c.witnesses,
			c.trustedStore,
			c.options...,
		)
		if err != nil {
			return fmt.Errorf("failed to create light client: %w", err)
		}

		c.lightClient = lightClient
		return nil
	})
}
