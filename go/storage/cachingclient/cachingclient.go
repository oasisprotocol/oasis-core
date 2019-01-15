package cachingclient

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"

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

	cacheCollectors = []prometheus.Collector{
		cacheHits,
		cacheMisses,
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
	if cached := b.cache.Get(key); cached != nil {
		cacheHits.Inc()
		return cached, nil
	}
	cacheMisses.Inc()
	return b.remote.Get(ctx, key)
}

func (b *cachingClientBackend) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	var missingKeys []api.Key
	var missingIdx []int

	values := make([][]byte, 0, len(keys))

	// Go through each key and try to retrieve its value from local cache.
	for _, key := range keys {
		if cached := b.cache.Get(key); cached != nil {
			cacheHits.Inc()
			values = append(values, cached)
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
		}
	}

	return values, nil
}

func (b *cachingClientBackend) Insert(ctx context.Context, value []byte, expiration uint64) error {
	// Write-through.
	err := b.remote.Insert(ctx, value, expiration)
	if err == nil {
		b.cache.Set(api.HashStorageKey(value), value)
	}
	return err
}

func (b *cachingClientBackend) InsertBatch(ctx context.Context, values []api.Value) error {
	// Write-through.
	err := b.remote.InsertBatch(ctx, values)
	if err == nil {
		for _, value := range values {
			b.cache.Set(api.HashStorageKey(value.Data), value.Data)
		}
	}
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
	}

	for _, v := range []string{
		cfgCacheFile,
		cfgCacheSize,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
