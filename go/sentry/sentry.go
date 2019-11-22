// Package sentry implements the sentry backend.
package sentry

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/sentry/api"
)

var _ api.Backend = (*backend)(nil)

type backend struct {
	logger *logging.Logger

	consensus consensus.Backend
}

func (b *backend) GetConsensusAddresses(ctx context.Context) ([]node.ConsensusAddress, error) {
	addrs, err := b.consensus.GetAddresses()
	if err != nil {
		return nil, fmt.Errorf("sentry: error obtaining consensus addresses: %w", err)
	}
	b.logger.Debug("successfully obtained consensus addresses",
		"addresses", addrs,
	)

	return addrs, nil
}

// New constructs a new sentry Backend instance.
func New(consensusBackend consensus.Backend) (api.Backend, error) {
	if consensusBackend == nil {
		return nil, fmt.Errorf("sentry: consensus backend is nil")
	}
	b := &backend{
		logger:    logging.GetLogger("sentry"),
		consensus: consensusBackend,
	}

	return b, nil
}
