// Package cachingclient implements a storage client wrapped with a
// disk-persisted in-memory local cache.
package cachingclient

import (
	"bufio"
	"context"
	"io"
	"os"
	"sync"

	"github.com/oasislabs/go-codec/codec"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
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

func (v *cachedValue) Size() uint64 {
	return uint64(len(v.value))
}

func (b *cachingClientBackend) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) (*api.MKVSReceipt, error) {
	// TODO: Implement caching for MKVS operations (issue #1664).
	return b.remote.Apply(ctx, root, expectedNewRoot, log)
}

func (b *cachingClientBackend) ApplyBatch(ctx context.Context, ops []api.ApplyOp) (*api.MKVSReceipt, error) {
	// TODO: Implement caching for MKVS operations (issue #1664).
	return b.remote.ApplyBatch(ctx, ops)
}

func (b *cachingClientBackend) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	// TODO: Implement caching for MKVS operations (issue #1664).
	return b.remote.GetSubtree(ctx, root, id, maxDepth)
}

func (b *cachingClientBackend) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	// TODO: Implement caching for MKVS operations (issue #1664).
	return b.remote.GetPath(ctx, root, key, startDepth)
}

func (b *cachingClientBackend) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	// TODO: Implement caching for MKVS operations (issue #1664).
	return b.remote.GetNode(ctx, root, id)
}

func (b *cachingClientBackend) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	// TODO: Implement caching for MKVS operations (issue #1664).
	return b.remote.GetValue(ctx, root, id)
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
	b.logger.Info("loading cache from disk",
		"path", b.dbPath,
	)

	f, err := os.Open(b.dbPath)
	if err != nil {
		if os.IsNotExist(err) {
			// This failure class is harmless, don't propagate the error.
			err = nil
		} else {
			b.logger.Error("failed to open persisted cache",
				"err", err,
			)
		}
		return err
	}
	defer f.Close()

	var (
		totalKeys int
		totalSize int

		r      = bufio.NewReader(f)
		ch     = make(chan []byte, 64) // Buffered, we're populating a cold cache.
		doneCh = make(chan struct{})
	)

	go func() {
		defer close(doneCh)
		for v := range ch {
			if b.insertLocal(api.HashStorageKey(v), append([]byte{}, v...)) {
				totalKeys++
				totalSize += len(v)
			}
		}
	}()

	dec := codec.NewDecoder(r, cbor.Handle)
	defer dec.Release()
	err = dec.Decode(&ch)
	close(ch)
	<-doneCh

	if err != nil && err != io.EOF {
		return errors.Wrap(err, "failed to de-serialize persisted cache")
	}

	b.logger.Info("loaded cache from disk",
		"keys", totalKeys,
		"bytes_written", totalSize,
	)

	return nil
}

func (b *cachingClientBackend) save() error {
	b.logger.Info("persisting cache to disk",
		"path", b.dbPath,
	)

	f, err := os.OpenFile(b.dbPath, os.O_CREATE|os.O_APPEND|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return errors.Wrap(err, "failed to open persisted cache for overwrite")
	}
	defer f.Close()

	var (
		totalKeys int
		totalSize int

		w  = bufio.NewWriter(f)
		ch = make(chan []byte) // Unbuffered, entries may be large.
	)
	defer w.Flush()

	go func() {
		defer close(ch)

		for _, v := range b.local.Keys() {
			cached, _ := b.local.Get(v)
			cachedBytes := cached.(*cachedValue).value
			ch <- cachedBytes

			totalSize += len(cachedBytes)
			totalKeys++
		}
	}()

	enc := codec.NewEncoder(w, cbor.Handle)
	defer enc.Release()
	if err = enc.Encode(ch); err != nil {
		return errors.Wrap(err, "failed to serialize/persist cache")
	}

	b.logger.Info("persisted cache to disk",
		"keys", totalKeys,
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
		lru.Capacity(uint64(viper.GetSizeInBytes(cfgCacheSize)), true),
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
		cmd.Flags().String(cfgCacheSize, "512mb", "Cache size (bytes)")
	}

	for _, v := range []string{
		cfgCacheFile,
		cfgCacheSize,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
