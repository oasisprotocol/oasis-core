// Package sentry implements the sentry backend.
package sentry

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
)

var _ api.Backend = (*backend)(nil)

type backend struct {
	sync.RWMutex

	logger *logging.Logger

	consensus consensus.Backend
	identity  *identity.Identity
}

func (b *backend) GetAddresses(ctx context.Context) (*api.SentryAddresses, error) {
	// Consensus addresses.
	consensusAddrs, err := b.consensus.GetAddresses()
	if err != nil {
		return nil, fmt.Errorf("sentry: error obtaining consensus addresses: %w", err)
	}
	b.logger.Debug("successfully obtained consensus addresses",
		"addresses", consensusAddrs,
	)

	return &api.SentryAddresses{
		Consensus: consensusAddrs,
	}, nil
}

// func (b *backend) GetPolicyChecker(ctx context.Context, service cmnGrpc.ServiceName) (*policy.DynamicRuntimePolicyChecker, error) {

// New constructs a new sentry Backend instance.
func New(
	consensusBackend consensus.Backend,
	identity *identity.Identity,
) (api.Backend, error) {
	if consensusBackend == nil {
		return nil, fmt.Errorf("sentry: consensus backend is nil")
	}

	b := &backend{
		logger:    logging.GetLogger("sentry"),
		consensus: consensusBackend,
		identity:  identity,
	}

	return b, nil
}
