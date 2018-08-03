package storage

import (
	"encoding/hex"
	"sync"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/epochtime"
)

var (
	_ Backend          = (*MemoryBackend)(nil)
	_ backendSweepable = (*MemoryBackend)(nil)
)

type memoryEntry struct {
	value      []byte
	expiration epochtime.EpochTime
}

// MemoryBackend is a memory backed storage backend.
//
// Data in this backend will be LOST on termination.
type MemoryBackend struct {
	sync.RWMutex

	logger     *logging.Logger
	timeSource epochtime.TimeSource
	store      map[Key]*memoryEntry
	sweeper    *backendSweeper
}

// Get returns the value for a specific immutable key.
func (b *MemoryBackend) Get(key Key) ([]byte, error) {
	epoch, _ := b.timeSource.GetEpoch()

	b.RLock()
	defer b.RUnlock()

	ent, ok := b.store[key]
	if !ok {
		return nil, ErrKeyNotFound
	}
	if ent.expiration < epoch {
		return nil, ErrKeyExpired
	}

	return append([]byte{}, ent.value...), nil
}

// Insert inserts a specific value, which can later be retreived by
// it's hash.  The expiration is the number of epochs for which the
// value should remain available.
func (b *MemoryBackend) Insert(value []byte, expiration uint64) error {
	key := HashStorageKey(value)
	epoch, _ := b.timeSource.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return ErrIncoherentTime
	}

	ent := &memoryEntry{
		value:      append([]byte{}, value...),
		expiration: epoch + epochtime.EpochTime(expiration),
	}

	b.logger.Debug("Insert",
		"key", key,
		"value", hex.EncodeToString(value),
		"expiration", ent.expiration,
	)

	b.Lock()
	defer b.Unlock()

	// XXX: This will unconditionally overwrite the expiration time
	// of existing entries.  Should it do something better?  (eg: Use
	// the longer of the two.)
	b.store[key] = ent

	return nil
}

// GetKeys returns all of the keys in the storage database, along
// with their associated metadata.
func (b *MemoryBackend) GetKeys() ([]*KeyInfo, error) {
	b.RLock()
	defer b.RUnlock()

	kiVec := make([]*KeyInfo, 0, len(b.store))
	for k, ent := range b.store {
		ki := &KeyInfo{
			Key:        k,
			Expiration: ent.expiration,
		}
		kiVec = append(kiVec, ki)
	}

	return kiVec, nil
}

// PurgeExpired purges keys that expire before the provided epoch.
func (b *MemoryBackend) PurgeExpired(epoch epochtime.EpochTime) {
	b.Lock()
	defer b.Unlock()

	for key, ent := range b.store {
		if ent.expiration < epoch {
			b.logger.Debug("Expire",
				"key", key,
			)
			delete(b.store, key)
		}
	}
}

// Cleanup closes/cleans up the storage backend.
func (b *MemoryBackend) Cleanup() {
	b.sweeper.Close()
}

// NewMemoryBackend constructs a new MemoryBackend instance.
func NewMemoryBackend(timeSource epochtime.TimeSource) Backend {
	b := &MemoryBackend{
		logger:     logging.GetLogger("MemoryStorageBackend"),
		timeSource: timeSource,
		store:      make(map[Key]*memoryEntry),
	}
	b.sweeper = newBackendSweeper(b, timeSource)

	return b
}
