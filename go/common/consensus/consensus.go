// Package consensus provides the implementation agnostic consesus
// backend.
package consensus

import "github.com/oasislabs/ekiden/go/common/node"

// Backend is an interface that a consensus backend must provide.
type Backend interface {
	// Synced returns a channel that is closed once synchronization is
	// complete.
	Synced() <-chan struct{}

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
