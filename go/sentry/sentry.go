// Package sentry implements the sentry backend.
package sentry

import (
	"context"
	"fmt"

	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/sentry/api"
	grpcSentry "github.com/oasislabs/oasis-core/go/worker/sentry/grpc"
)

var _ api.Backend = (*backend)(nil)

type backend struct {
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

	// Committee addresses - only available if gRPC sentry is enabled.
	committeeAddrs, err := grpcSentry.GetNodeAddresses()
	if err != nil {
		return nil, fmt.Errorf("sentry: error obtaining sentry worker addresses: %w", err)
	}
	var committeeAddresses []node.CommitteeAddress
	for _, addr := range committeeAddrs {
		committeeAddresses = append(committeeAddresses, node.CommitteeAddress{
			Certificate: b.identity.GetTLSCertificate().Certificate[0],
			Address:     addr,
		})
	}

	return &api.SentryAddresses{
		Committee: committeeAddresses,
		Consensus: consensusAddrs,
	}, nil
}

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
