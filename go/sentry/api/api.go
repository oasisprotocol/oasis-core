// Package api implements the sentry backend API.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/node"
)

// SentryAddresses contains sentry node consensus and committee addresses.
type SentryAddresses struct {
	Consensus []node.ConsensusAddress
	Committee []node.CommitteeAddress
}

// Backend is a sentry backend implementation.
type Backend interface {
	// Get addresses returns the list of consensus and committee addresses of
	// the sentry node.
	GetAddresses(context.Context) (*SentryAddresses, error)
}
