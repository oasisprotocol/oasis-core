package common

// ConsensusBackend is an interface that a consensus backend must provide.
type ConsensusBackend interface {
	// Synced returns a channel that is closed once synchronization is
	// complete.
	Synced() <-chan struct{}

	// RegisterGenesisHook registers a function to be called when the
	// consensus backend is initialized from genesis (e.g., on fresh
	// start).
	//
	// Note that these hooks block consensus genesis from completing
	// while they are running.
	RegisterGenesisHook(func())
}
