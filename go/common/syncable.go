package common

// Syncable is an interface exposed by consensus backends that expose
// a way to block on initial synchronization.
type Syncable interface {
	// Synced returns a channel that is closed once synchronization is complete.
	Synced() <-chan struct{}
}
