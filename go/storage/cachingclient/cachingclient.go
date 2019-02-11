package cachingclient

import (
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/cachingclient/cache"
	"github.com/oasislabs/ekiden/go/storage/client"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "cachingclient"

	// Path to file for persistent cache storage.
	cfgCacheFile = "storage.cachingclient.file"

	// Number of cache entries.
	cfgCacheSize = "storage.cachingclient.cache_size"

	// Maximum async write-back batch backlog.
	cfgCacheBacklog = "storage.cachingclient.async_backlog"
)

var (
	_ api.Backend = (*cachingClientBackend)(nil)

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
	cache  *cache.Cache
}

func (b *cachingClientBackend) Get(ctx context.Context, key api.Key) ([]byte, error) {
	// Try local cache first, then remote node if missing.
	cached, err := b.cache.Get(key)
	if cached != nil {
		cacheHits.Inc()
		return cached, nil
	}
	if err != api.ErrKeyNotFound {
		return nil, err
	}

	cacheMisses.Inc()
	value, err := b.remote.Get(ctx, key)
	if err == api.ErrKeyNotFound {
		remoteMisses.Inc()
	} else if err == nil {
		b.cache.SetBatchAsync([]cache.KeyValue{cache.KeyValue{Key: key, Value: value}})
	}

	return value, err
}

func (b *cachingClientBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	var missingKeys []api.Key
	var missingIdx []int

	values := make([][]byte, 0, len(keys))

	// Go through each key and try to retrieve its value from local cache.
	for _, key := range keys {
		cached, err := b.cache.Get(key)
		switch err {
		case nil:
			cacheHits.Inc()
			values = append(values, cached)
		case api.ErrKeyNotFound:
			// Cache miss, add to batch for remote.
			cacheMisses.Inc()
			values = append(values, nil)
			missingKeys = append(missingKeys, key)
			missingIdx = append(missingIdx, len(values)-1)
		default:
			return nil, err
		}
	}

	// Fetch missing values from remote node.
	if len(missingKeys) > 0 {
		remote, err := b.remote.GetBatch(ctx, missingKeys)
		if err != nil {
			return nil, err
		}

		var kvs []cache.KeyValue
		for remoteIdx, idx := range missingIdx {
			values[idx] = remote[remoteIdx]
			kvs = append(kvs, cache.KeyValue{Key: missingKeys[idx], Value: values[idx]})
		}

		b.cache.SetBatchAsync(kvs)
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
		b.cache.Set(api.HashStorageKey(value), value)
	}
	return err
}

func (b *cachingClientBackend) InsertBatch(ctx context.Context, values []api.Value, opts api.InsertOptions) error {
	// Write-through. Since storage insert operations are currently idempotent, we can
	// parallelize remote insert and cache insert.
	ch := make(chan struct{})
	go func() {
		var kvs []cache.KeyValue
		for _, value := range values {
			kvs = append(kvs, cache.KeyValue{Key: api.HashStorageKey(value.Data), Value: value.Data})
		}

		b.cache.SetBatch(kvs)

		close(ch)
	}()

	var err error
	if !opts.LocalOnly {
		err = b.remote.InsertBatch(ctx, values, opts)
	}

	<-ch

	return err
}

func (b *cachingClientBackend) GetKeys(ctx context.Context) (<-chan *api.KeyInfo, error) {
	// This must always be fetched from remote.
	return b.remote.GetKeys(ctx)
}

func (b *cachingClientBackend) Cleanup() {
	b.remote.Cleanup()
	b.cache.Cleanup()
}

func (b *cachingClientBackend) Initialized() <-chan struct{} {
	return b.remote.Initialized()
}

func New() (api.Backend, error) {
	// Register metrics for cache hits and misses.
	metricsOnce.Do(func() {
		prometheus.MustRegister(cacheCollectors...)
	})

	// The remote node address needs to be set with the
	// "storage.client.address" config parameter.
	remote, err := client.New()
	if err != nil {
		return nil, err
	}

	cache, err := cache.New(
		viper.GetString(cfgCacheFile),
		viper.GetInt(cfgCacheSize),
		viper.GetInt(cfgCacheBacklog),
	)
	if err != nil {
		return nil, err
	}

	b := &cachingClientBackend{
		logger: logging.GetLogger("storage/cachingclient"),
		remote: remote,
		cache:  cache,
	}

	return b, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgCacheFile, "cachingclient.storage.leveldb", "Path to file for persistent cache storage")
		cmd.Flags().Int(cfgCacheSize, 1000000, "Cache size")
		cmd.Flags().Int(cfgCacheBacklog, 64, "Cache async backlog")
	}

	for _, v := range []string{
		cfgCacheFile,
		cfgCacheSize,
		cfgCacheBacklog,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
