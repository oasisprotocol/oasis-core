package light

import (
	"github.com/cometbft/cometbft/light/store"
	cmttypes "github.com/cometbft/cometbft/types"
)

// prunedStore is a light block store that automatically prunes old blocks.
//
// When the number of stored blocks exceeds the high watermark, it prunes
// blocks until the number of stored blocks reaches the low watermark.
type prunedStore struct {
	store store.Store
	high  uint16
	low   uint16
}

// newPrunedStore creates a new store backed by the given store,
// configured with high and low watermarks.
//
// If high is set to zero, automatic pruning is disabled.
func newPrunedStore(store store.Store, high uint16, low uint16) *prunedStore {
	return &prunedStore{
		store: store,
		high:  high,
		low:   low,
	}
}

// DeleteLightBlock implements store.Store.
func (p *prunedStore) DeleteLightBlock(height int64) error {
	return p.store.DeleteLightBlock(height)
}

// FirstLightBlockHeight implements store.Store.
func (p *prunedStore) FirstLightBlockHeight() (int64, error) {
	return p.store.FirstLightBlockHeight()
}

// LastLightBlockHeight implements store.Store.
func (p *prunedStore) LastLightBlockHeight() (int64, error) {
	return p.store.LastLightBlockHeight()
}

// LightBlock implements store.Store.
func (p *prunedStore) LightBlock(height int64) (*cmttypes.LightBlock, error) {
	return p.store.LightBlock(height)
}

// LightBlockBefore implements store.Store.
func (p *prunedStore) LightBlockBefore(height int64) (*cmttypes.LightBlock, error) {
	return p.store.LightBlockBefore(height)
}

// Prune implements store.Store.
func (p *prunedStore) Prune(size uint16) error {
	return p.store.Prune(size)
}

// SaveLightBlock implements store.Store.
func (p *prunedStore) SaveLightBlock(lb *cmttypes.LightBlock) error {
	if p.high > 0 && p.Size() >= p.high {
		if err := p.Prune(p.low); err != nil {
			return err
		}
	}
	return p.store.SaveLightBlock(lb)
}

// Size implements store.Store.
func (p *prunedStore) Size() uint16 {
	return p.store.Size()
}
