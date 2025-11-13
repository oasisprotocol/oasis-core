// Package light implements a CometBFT light client service.
package light

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
)

const (
	// numWitnesses is the number of libp2p backed CometBFT light-block witnesses to be instantiated.
	numWitnesses = 2
	// lcMaxRetryAttempts is the number of retry attempts the CometBFT light client does,
	// before switching the primary provider.
	lcMaxRetryAttempts = 5
)

type ClientService struct {
	logger *logging.Logger

	providers []*Provider
}

// GetStatus implements api.LightService.
func (c *ClientService) GetStatus() (*consensus.LightClientStatus, error) {
	status := &consensus.LightClientStatus{}

	for _, p := range c.providers {
		if id := p.PeerID(); id != "" {
			status.PeerIDs = append(status.PeerIDs, id)
		}
	}

	return status, nil
}

// TrustedLightBlock implements the LightClient interface.
func (c *ClientService) TrustedLightBlock(int64) (*consensus.LightBlock, error) {
	return nil, fmt.Errorf("light block not found")
}

// LightBlock implements the LightProvider interface.
func (c *ClientService) LightBlock(ctx context.Context, height int64) (*consensus.LightBlock, error) {
	rsp, _, err := tryProviders(ctx, c.providers, func(p *Provider) (*lightBlock, rpc.PeerFeedback, error) {
		return p.getLightBlock(ctx, height)
	})
	if err != nil {
		c.logger.Debug("failed to fetch light block from peer",
			"err", err,
			"height", height,
		)
		return nil, err
	}
	return rsp.lb, nil
}

// New creates a new CometBFT light client service backed by the local full node.
//
// This light client is initialized with a trusted blocks obtained from the local consensus backend.
func New(ctx context.Context, chainContext string, p2p rpc.P2P) (*ClientService, error) {
	pool := NewProviderPool(ctx, chainContext, p2p)
	providers := make([]*Provider, 0, numWitnesses)
	for range numWitnesses {
		p := pool.NewProvider()
		providers = append(providers, p)
	}

	return &ClientService{
		logger:    logging.GetLogger("consensus/cometbft/light"),
		providers: providers,
	}, nil
}
