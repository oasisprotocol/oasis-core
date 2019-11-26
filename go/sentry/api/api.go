// Package api implements the sentry backend API.
package api

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/node"
)

// Backend is a sentry backend implementation.
type Backend interface {
	// GetConsensusAddresses returns the list of consensus addresses of the sentry node.
	GetConsensusAddresses(context.Context) ([]node.ConsensusAddress, error)
}
