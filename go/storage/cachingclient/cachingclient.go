// Package cachingclient implements a storage client wrapped with a
// disk-persisted in-memory local cache.
package cachingclient

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	dbm "github.com/tendermint/tendermint/libs/db"

	"github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "cachingclient"

	// Path to file for persistent cache storage.
	cfgCacheFile = "storage.cachingclient.file"

	// Size of the cache in bytes.
	cfgCacheSize = "storage.cachingclient.cache_size"
)

var (
	_ api.Backend  = (*cachingClientBackend)(nil)
	_ lru.Sizeable = (*cachedValue)(nil)

	cacheHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_cachingclient_cache_hits",
			Help: "Number of cache hits to local cache in caching remote storage client backend.",
		},
	)
	cacheMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_cachingclient_cache_misses",
			Help: "Number of cache misses from local cache in caching remote storage client backend.",
		},
	)
	remoteMisses = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_cachingclient_remote_misses",
			Help: "Number of queries for non-existent keys.",
		},
	)

	cacheCollectors = []prometheus.Collector{
		cacheHits,
		cacheMisses,
		remoteMisses,
	}

	metricsOnce sync.Once
)

type cachingClientBackend struct {
	logger *logging.Logger

	remote api.Backend
	local  *lru.Cache

	dbPath string
}

type cachedValue struct {
	value []byte
}

func (v *cachedValue) Size() int {
	return len(v.value)
}

func (b *cachingClientBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	// Try local cache first, then remote node if missing.
	cached, ok := b.local.Get(key)
	if ok {
		cacheHits.Inc()
		return cached.(*cachedValue).value, nil
	}

	cacheMisses.Inc()
	value, err := b.remote.Get(ctx, key)
	if err == api.ErrKeyNotFound {
		remoteMisses.Inc()
	} else if err == nil {
		b.insertLocal(key, value)
	}

	return value, err
}

func (b *cachingClientBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	var missingKeys []api.Key
	var missingIdx []int

	values := make([][]byte, 0, len(keys))

	// Go through each key and try to retrieve its value from local cache.
	for _, key := range keys {
		if cached, ok := b.local.Get(key); ok {
			cacheHits.Inc()
			values = append(values, cached.(*cachedValue).value)
		} else {
			// Cache miss, add to batch for remote.
			cacheMisses.Inc()
			values = append(values, nil)
			missingKeys = append(missingKeys, key)
			missingIdx = append(missingIdx, len(values)-1)
		}
	}

	// Fetch missing values from remote node.
	if len(missingKeys) > 0 {
		remote, err := b.remote.GetBatch(ctx, missingKeys)
		if err != nil {
			return nil, err
		}

		for remoteIdx, idx := range missingIdx {
			values[idx] = remote[remoteIdx]
			b.insertLocal(missingKeys[idx], values[idx])
		}
	}

	return values, nil
}

func (b *cachingClientBackend) GetReceipt(ctx context.Context, keys []api.Key) (*api.SignedReceipt, error) {
	return b.remote.GetReceipt(ctx, keys)
}

func (b *cachingClientBackend) Insert(ctx context.Context, value []byte, expiration uint64, opts api.InsertOptions) error {
	// Write-through.
	var err error
	if !opts.LocalOnly {
		err = b.remote.Insert(ctx, value, expiration, opts)
	}
	if err == nil {
		b.insertLocal(api.HashStorageKey(value), value)
	}
	return err
}

func (b *cachingClientBackend) InsertBatch(ctx context.Context, values []api.Value, opts api.InsertOptions) error {
	localFunc := func() {
		for _, value := range values {
			b.insertLocal(api.HashStorageKey(value.Data), value.Data)
		}
	}

	var err error
	switch opts.LocalOnly {
	case true:
		localFunc()
	default:
		// Write-through. Since storage insert operations are currently idempotent,
		// we can parallelize remote insert and cache insert.
		ch := make(chan struct{})

		go func() {
			localFunc()
			close(ch)
		}()

		err = b.remote.InsertBatch(ctx, values, opts)
		<-ch
	}

	return err
}

func (b *cachingClientBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	// This must always be fetched from remote.
	return b.remote.GetKeys(ctx)
}

func (b *cachingClientBackend) Cleanup() {
	b.remote.Cleanup()
	if err := b.save(); err != nil {
		b.logger.Error("failed to persist cache to disk",
			"err", err,
		)
	}
}

func (b *cachingClientBackend) Initialized() <-chan struct{} {
	return b.remote.Initialized()
}

func (b *cachingClientBackend) insertLocal(key api.Key, value []byte) bool {
	err := b.local.Put(key, &cachedValue{value: value})
	if err == nil {
		return true
	}

	b.logger.Error("failed to insert into cache",
		"err", err,
		"key", key,
		"value_size", len(value),
	)
	return false
}

func (b *cachingClientBackend) load() error {
	dir, file := filepath.Split(b.dbPath)
	db := dbm.NewDB(file, dbm.LevelDBBackend, dir)
	defer db.Close()

	b.logger.Info("loading cache to disk",
		"path", b.dbPath,
	)

	var (
		totalKeys int
		totalSize int
	)

	iter := db.Iterator(nil, nil)
	defer iter.Close()
	for ; iter.Valid(); iter.Next() {
		v := iter.Value()

		if b.insertLocal(api.HashStorageKey(v), append([]byte{}, v...)) {
			totalKeys++
			totalSize += len(v)
		}
	}

	b.logger.Info("loaded cache from disk",
		"keys", totalKeys,
		"bytes_written", totalSize,
	)

	return nil
}

func (b *cachingClientBackend) save() error {
	// Blow away the old cache.
	if err := os.RemoveAll(b.dbPath); err != nil {
		return errors.Wrap(err, "failed to remove existing cache")
	}

	b.logger.Info("persisting cache to disk",
		"path", b.dbPath,
	)

	dir, file := filepath.Split(b.dbPath)
	db := dbm.NewDB(file, dbm.LevelDBBackend, dir)
	defer db.Close()

	var (
		batch = db.NewBatch()
		keys  = b.local.Keys()
	)

	var totalSize int
	for i, v := range keys {
		var dbKey [8]byte
		binary.BigEndian.PutUint64(dbKey[:], uint64(i))
		cached, _ := b.local.Get(v)
		cachedBytes := cached.(*cachedValue).value
		batch.Set(dbKey[:], cachedBytes)
		totalSize += len(cachedBytes)
	}

	batch.Write()

	b.logger.Info("persisted cache to disk",
		"keys", len(keys),
		"bytes_written", totalSize,
	)

	return nil
}

func New(remote api.Backend) (api.Backend, error) {
	// Register metrics for cache hits and misses.
	metricsOnce.Do(func() {
		prometheus.MustRegister(cacheCollectors...)
	})

	local, err := lru.New(
		lru.Capacity(viper.GetInt(cfgCacheSize), true),
	)
	if err != nil {
		return nil, err
	}

	b := &cachingClientBackend{
		logger: logging.GetLogger("storage/cachingclient"),
		remote: remote,
		local:  local,
		dbPath: viper.GetString(cfgCacheFile),
	}
	if err := b.load(); err != nil {
		return nil, err
	}

	return b, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgCacheFile, "cachingclient.storage.leveldb", "Path to file for persistent cache storage")
		cmd.Flags().Int(cfgCacheSize, 512*1024*1024, "Cache size (bytes)")
	}

	for _, v := range []string{
		cfgCacheFile,
		cfgCacheSize,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
