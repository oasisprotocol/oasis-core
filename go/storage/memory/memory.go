// Package memory implements the memory backed storage backend.
package memory

import (
	"encoding/hex"
	"sync"

	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/logging"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/storage/api"
)

// BackendName is the name of this implementation.
const BackendName = "memory"

var (
	_ api.Backend          = (*memoryBackend)(nil)
	_ api.SweepableBackend = (*memoryBackend)(nil)
)

type memoryEntry struct {
	value      []byte
	expiration epochtime.EpochTime
}

type memoryBackend struct {
	sync.RWMutex

	logger     *logging.Logger
	timeSource epochtime.Backend
	store      map[api.Key]*memoryEntry
	sweeper    *api.Sweeper
}

func (b *memoryBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	epoch, _, err := b.timeSource.GetEpoch(ctx)
	if err != nil {
		return nil, err
	}

	b.RLock()
	defer b.RUnlock()

	ent, ok := b.store[key]
	if !ok {
		return nil, api.ErrKeyNotFound
	}
	if ent.expiration < epoch {
		return nil, api.ErrKeyExpired
	}

	return append([]byte{}, ent.value...), nil
}

func (b *memoryBackend) Insert(ctx context.Context, value []byte, expiration uint64) error {
	epoch, _, err := b.timeSource.GetEpoch(ctx)
	if err != nil {
		return err
	}
	if epoch == epochtime.EpochInvalid {
		return api.ErrIncoherentTime
	}

	key := api.HashStorageKey(value)
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

func (b *memoryBackend) GetKeys(ctx context.Context) ([]*api.KeyInfo, error) {
	b.RLock()
	defer b.RUnlock()

	kiVec := make([]*api.KeyInfo, 0, len(b.store))
	for k, ent := range b.store {
		ki := &api.KeyInfo{
			Key:        k,
			Expiration: ent.expiration,
		}
		kiVec = append(kiVec, ki)
	}

	return kiVec, nil
}

func (b *memoryBackend) PurgeExpired(epoch epochtime.EpochTime) {
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

func (b *memoryBackend) Cleanup() {
	b.sweeper.Close()
}

// New constructs a new memory backed storage Backend instance.
func New(timeSource epochtime.Backend) api.Backend {
	b := &memoryBackend{
		logger:     logging.GetLogger("storage/memory"),
		timeSource: timeSource,
		store:      make(map[api.Key]*memoryEntry),
	}
	b.sweeper = api.NewSweeper(b, timeSource)

	return b
}
