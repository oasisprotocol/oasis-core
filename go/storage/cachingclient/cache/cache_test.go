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

func TestBasic(t *testing.T) {
	cacheSize := 10
	extraItems := 1

	cacheDir, err := ioutil.TempDir("", "ekiden-cachingclient-test_")
	require.NoError(t, err, "create cache dir")
	defer os.RemoveAll(cacheDir)

	cache, err := New(filepath.Join(cacheDir, "db"), cacheSize)
	require.NoError(t, err, "New")

	for i := 0; i < cacheSize+extraItems; i++ {
		value := []byte(fmt.Sprintf("value-%d", i))
		key := api.HashStorageKey(value)

		cache.Set(key, value)
		cachedValue := cache.Get(key)
		require.EqualValues(t, value, cachedValue)
	}

	valuesInCache := 0
	for i := 0; i < cacheSize+extraItems; i++ {
		value := []byte(fmt.Sprintf("value-%d", i))
		key := api.HashStorageKey(value)

		cachedValue := cache.Get(key)
		if cachedValue != nil {
			valuesInCache++
			require.EqualValues(t, value, cachedValue)
		}
	}

	require.Equal(t, cacheSize, valuesInCache)
}

func TestBatchSet(t *testing.T) {
	cacheSize := 10
	extraItems := 1

	cacheDir, err := ioutil.TempDir("", "ekiden-cachingclient-test_")
	require.NoError(t, err, "create cache dir")
	defer os.RemoveAll(cacheDir)

	cache, err := New(filepath.Join(cacheDir, "db"), cacheSize)
	require.NoError(t, err, "New")

	var kvs []KeyValue
	for i := 0; i < cacheSize+extraItems; i++ {
		value := []byte(fmt.Sprintf("value-%d", i))
		key := api.HashStorageKey(value)

		kvs = append(kvs, KeyValue{key, value})
	}

	cache.SetBatch(kvs)

	valuesInCache := 0
	for i := 0; i < cacheSize+extraItems; i++ {
		value := []byte(fmt.Sprintf("value-%d", i))
		key := api.HashStorageKey(value)

		cachedValue := cache.Get(key)
		if cachedValue != nil {
			valuesInCache++
			require.EqualValues(t, value, cachedValue)
		}
	}

	require.Equal(t, cacheSize, valuesInCache)
}
