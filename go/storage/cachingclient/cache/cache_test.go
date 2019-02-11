package cache

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/storage/api"
)

const (
	cacheSize  = 10
	extraItems = 1
	backlog    = 5
)

func TestBasic(t *testing.T) {
	cache, cacheDir := requireNewCache(t)
	defer func() {
		os.RemoveAll(cacheDir)
		cache.Cleanup()
	}()

	kvs := makeTestKeyValues(cacheSize + extraItems)
	for _, v := range kvs {
		cache.Set(v.Key, v.Value)

		cachedValue, err := cache.Get(v.Key)
		require.EqualValues(t, v.Value, cachedValue)
		require.NoError(t, err, "Get(hit)")
	}

	var valuesInCache int
	for _, v := range kvs {
		if requireGet(t, cache, v.Key, v.Value) {
			valuesInCache++
		}
	}
	require.Equal(t, cacheSize, valuesInCache)
}

func TestBatchSet(t *testing.T) {
	cache, cacheDir := requireNewCache(t)
	defer func() {
		os.RemoveAll(cacheDir)
		cache.Cleanup()
	}()

	kvs := makeTestKeyValues(cacheSize + extraItems)
	cache.SetBatch(kvs)

	var valuesInCache int
	for _, v := range kvs {
		if requireGet(t, cache, v.Key, v.Value) {
			valuesInCache++
		}
	}
	require.Equal(t, cacheSize, valuesInCache)
}

func TestAsyncSet(t *testing.T) {
	cache, cacheDir := requireNewCache(t)
	defer func() {
		os.RemoveAll(cacheDir)
		// Leaves cache dangling, but whatever, this is a test case.
	}()

	kvs := makeTestKeyValues(cacheSize + extraItems)
	cache.SetBatchAsync(kvs)

	cache.Cleanup() // Force flush to disk.

	var err error
	cache, err = New(filepath.Join(cacheDir, "db"), cacheSize, backlog)
	require.NoError(t, err, "New(reopen)")

	var valuesInCache int
	for _, v := range kvs {
		if requireGet(t, cache, v.Key, v.Value) {
			valuesInCache++
		}
	}
	require.Equal(t, cacheSize, valuesInCache)
}

func requireNewCache(t *testing.T) (*Cache, string) {
	cacheDir, err := ioutil.TempDir("", "ekiden-cachingclient-test_")
	require.NoError(t, err, "create cache dir")

	cache, err := New(filepath.Join(cacheDir, "db"), cacheSize, backlog)
	if err != nil {
		os.RemoveAll(cacheDir)
	}
	require.NoError(t, err, "New")

	return cache, cacheDir
}

func makeTestKeyValues(n int) []KeyValue {
	var kvs []KeyValue
	for i := 0; i < n; i++ {
		v := []byte(fmt.Sprintf("value-%d", i))
		kvs = append(kvs, KeyValue{
			Key:   api.HashStorageKey(v),
			Value: v,
		})
	}

	return kvs
}

func requireGet(t *testing.T, cache *Cache, key api.Key, expected []byte) bool {
	value, err := cache.Get(key)
	switch value {
	case nil:
		require.Error(t, err, "Get(miss)")
		require.Equal(t, api.ErrKeyNotFound, err, "Get(miss) error is ErrKeyNotFound")
		return false
	default:
		require.NoError(t, err, "Get(hit)")
		require.EqualValues(t, expected, value, "Get() returned expected value")
		return true
	}
}
