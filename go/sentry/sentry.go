// Package sentry implements the sentry backend.
package sentry

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/sentry/api"
	grpcSentry "github.com/oasisprotocol/oasis-core/go/worker/sentry/grpc"
)

var _ api.Backend = (*backend)(nil)

type backend struct {
	sync.RWMutex

	logger *logging.Logger

	consensus consensus.Backend
	identity  *identity.Identity

	upstreamTLSPubKeys []signature.PublicKey
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

	// TLS addresses -- only available if gRPC sentry is enabled.
	tlsAddrs, err := grpcSentry.GetNodeAddresses()
	if err != nil {
		return nil, fmt.Errorf("sentry: error obtaining sentry worker addresses: %w", err)
	}
	var tlsAddresses []node.TLSAddress

	for _, addr := range tlsAddrs {
		tlsAddresses = append(tlsAddresses, node.TLSAddress{
			PubKey:  b.identity.GetTLSSigner().Public(),
			Address: addr,
		})
		// Make sure to also include the certificate that will be valid
		// in the next epoch, so that the node remains reachable.
		if nextSigner := b.identity.GetNextTLSSigner(); nextSigner != nil {
			tlsAddresses = append(tlsAddresses, node.TLSAddress{
				PubKey:  nextSigner.Public(),
				Address: addr,
			})
		}
	}

	return &api.SentryAddresses{
		Consensus: consensusAddrs,
		TLS:       tlsAddresses,
	}, nil
}

func (b *backend) SetUpstreamTLSPubKeys(ctx context.Context, pubKeys []signature.PublicKey) error {
	b.Lock()
	defer b.Unlock()

	b.upstreamTLSPubKeys = pubKeys

	return nil
}

func (b *backend) GetUpstreamTLSPubKeys(ctx context.Context) ([]signature.PublicKey, error) {
	b.RLock()
	defer b.RUnlock()

	return b.upstreamTLSPubKeys, nil
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
