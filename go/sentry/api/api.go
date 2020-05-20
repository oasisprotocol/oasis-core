// Package api implements the sentry backend API.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
)

// SentryAddresses contains sentry node consensus and TLS addresses.
type SentryAddresses struct {
	Consensus []node.ConsensusAddress `json:"consensus"`
	TLS       []node.TLSAddress       `json:"tls"`
}

// Backend is a sentry backend implementation.
type Backend interface {
	// Get addresses returns the list of consensus and TLS addresses of the sentry node.
	GetAddresses(context.Context) (*SentryAddresses, error)

	// SetUpstreamTLSPubKeys notifies the sentry node of the new TLS public keys used by its
	// upstream node.
	SetUpstreamTLSPubKeys(context.Context, []signature.PublicKey) error

	// GetUpstreamTLSPubKeys returns the TLS public keys of the sentry node's upstream node.
	GetUpstreamTLSPubKeys(context.Context) ([]signature.PublicKey, error)
}
