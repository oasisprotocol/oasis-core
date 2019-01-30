// Package memory implements the memory backed storage backend.
package memory

import (
	"encoding/hex"
	"sync"

	"github.com/opentracing/opentracing-go"
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

	logger  *logging.Logger
	store   map[api.Key]*memoryEntry
	sweeper *api.Sweeper
}

func (b *memoryBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	epoch := b.sweeper.GetEpoch()
	if epoch == epochtime.EpochInvalid {
		return nil, api.ErrIncoherentTime
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

func (b *memoryBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	var values [][]byte
	for _, key := range keys {
		value, err := b.Get(ctx, key)
		if err != nil {
			switch err {
			case nil, api.ErrKeyNotFound, api.ErrKeyExpired:
				break
			default:
				return nil, err
			}
		}

		values = append(values, value)
	}

	return values, nil
}

func (b *memoryBackend) Insert(ctx context.Context, value []byte, expiration uint64, opts api.InsertOptions) error {
	epoch := b.sweeper.GetEpoch()
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

	span, _ := opentracing.StartSpanFromContext(ctx, "storage-memory-lock-set", opentracing.Tag{Key: "ekiden.storage_key", Value: key})

	b.Lock()
	defer b.Unlock()

	// XXX: This will unconditionally overwrite the expiration time
	// of existing entries.  Should it do something better?  (eg: Use
	// the longer of the two.)
	b.store[key] = ent

	span.Finish()

	return nil
}

func (b *memoryBackend) InsertBatch(ctx context.Context, values []api.Value, opts api.InsertOptions) error {
	// No atomicity for in-memory backend, we just repeatedly insert.
	for _, value := range values {
		if err := b.Insert(ctx, value.Data, value.Expiration, opts); err != nil {
			return err
		}
	}

	return nil
}

func (b *memoryBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	kiChan := make(chan *api.KeyInfo)

	go func() {
		b.RLock()
		defer b.RUnlock()
		defer close(kiChan)

		for k, ent := range b.store {
			ki := api.KeyInfo{
				Key:        k,
				Expiration: ent.expiration,
			}
			select {
			case kiChan <- &ki:
			case <-ctx.Done():
				break
			}
		}
	}()

	return kiChan, nil
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

func (b *memoryBackend) Initialized() <-chan struct{} {
	return b.sweeper.Initialized()
}

// New constructs a new memory backed storage Backend instance.
func New(timeSource epochtime.Backend) api.Backend {
	b := &memoryBackend{
		logger: logging.GetLogger("storage/memory"),
		store:  make(map[api.Key]*memoryEntry),
	}
	b.sweeper = api.NewSweeper(b, timeSource)

	return b
}
