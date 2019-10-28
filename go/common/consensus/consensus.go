// Package consensus provides the implementation agnostic consesus
// backend.
package consensus

import (
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
)

// Backend is an interface that a consensus backend must provide.
type Backend interface {
	// Synced returns a channel that is closed once synchronization is
	// complete.
	Synced() <-chan struct{}

	// ConsensusKey returns the consensus signing key.
	ConsensusKey() signature.PublicKey

	// GetAddresses returns the consensus backend addresses.
	GetAddresses() ([]node.Address, error)

	// RegisterGenesisHook registers a function to be called when the
	// consensus backend is initialized from genesis (e.g., on fresh
	// start).
	//
	// Note that these hooks block consensus genesis from completing
	// while they are running.
	RegisterGenesisHook(func())
}
