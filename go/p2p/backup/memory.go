package backup

import (
	"context"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"
)

var _ Backend = (*commonStoreBackend)(nil)

// InMemoryBackend uses memory to backup and restore peers. This backend is not persistent and
// intended for testing purposes only.
type InMemoryBackend struct {
	mu      sync.Mutex
	nsPeers map[string][]peer.AddrInfo
}

// NewInMemoryBackend creates a new in-memory backend.
func NewInMemoryBackend() *InMemoryBackend {
	return &InMemoryBackend{
		nsPeers: make(map[string][]peer.AddrInfo),
	}
}

// Delete implements PeerBackup.
func (b *InMemoryBackend) Delete(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nsPeers = make(map[string][]peer.AddrInfo)
	return nil
}

// Backup implements PeerBackup.
func (b *InMemoryBackend) Backup(_ context.Context, nsPeers map[string][]peer.AddrInfo) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nsPeers = nsPeers
	return nil
}

// Restore implements PeerBackup.
func (b *InMemoryBackend) Restore(context.Context) (map[string][]peer.AddrInfo, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.nsPeers, nil
}
