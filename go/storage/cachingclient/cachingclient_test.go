package cachingclient

import (
	"context"
	"crypto"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/memory"
)

const (
	cacheSize  = 10
	extraItems = 1
)

type keyValue struct {
	Key   api.Key
	Value []byte
}

func TestSingleAndPersistence(t *testing.T) {
	remote := memory.New(mock.New(), nil)
	client, cacheDir := requireNewClient(t, remote)
	defer func() {
		os.RemoveAll(cacheDir)
	}()

	var err error

	kvs := makeTestKeyValues([]byte("TestSingle"), cacheSize+extraItems)
	for _, v := range kvs {
		err = client.Insert(context.Background(), v.Value, 666, api.InsertOptions{LocalOnly: true})
		require.NoError(t, err, "Insert")
	}

	requireKVs(t, client, kvs, cacheSize)

	// Test the persistence.
	client.Cleanup()
	remote = memory.New(mock.New(), nil)
	client, err = New(remote)
	require.NoError(t, err, "New - reopen")

	requireKVs(t, client, kvs, cacheSize)
}

func TestBatch(t *testing.T) {
	remote := memory.New(mock.New(), nil)
	client, cacheDir := requireNewClient(t, remote)
	defer func() {
		client.Cleanup()
		os.RemoveAll(cacheDir)
	}()

	kvs := makeTestKeyValues([]byte("TestBatch"), cacheSize+extraItems)
	var (
		ks []api.Key
		vs []api.Value
	)
	for _, v := range kvs {
		vs = append(vs, api.Value{
			Data:       v.Value,
			Expiration: 666,
		})
		ks = append(ks, v.Key)
	}

	err := client.InsertBatch(context.Background(), vs, api.InsertOptions{LocalOnly: false})
	require.NoError(t, err, "InsertBatch")

	values, err := client.GetBatch(context.Background(), ks)
	require.NoError(t, err, "GetBatch")
	for i, v := range values {
		require.EqualValues(t, kvs[i].Value, v, "GetBatch - value: %d", i)
	}
}

func requireNewClient(t *testing.T, remote api.Backend) (api.Backend, string) {
	cacheDir, err := ioutil.TempDir("", "ekiden-cachingclient-test_")
	require.NoError(t, err, "create cache dir")

	viper.Set(cfgCacheFile, filepath.Join(cacheDir, "db"))
	viper.Set(cfgCacheSize, cacheSize)
	viper.Set(cfgCacheMaxValueSize, 1024)

	client, err := New(remote)
	if err != nil {
		os.RemoveAll(cacheDir)
	}
	require.NoError(t, err, "New")

	return client, cacheDir
}

func requireGet(t *testing.T, client api.Backend, key api.Key, expected []byte) bool {
	value, err := client.Get(context.Background(), key)
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

func requireKVs(t *testing.T, client api.Backend, kvs []keyValue, expectedHits int) {
	var valuesInCache int
	for _, v := range kvs {
		if requireGet(t, client, v.Key, v.Value) {
			valuesInCache++
		}
	}
	require.Equal(t, expectedHits, valuesInCache, "Cache has expected number of entries")
}

func makeTestKeyValues(seed []byte, n int) []keyValue {
	h := crypto.SHA512.New()
	_, _ = h.Write(seed)
	drbg, err := drbg.New(crypto.SHA256, h.Sum(nil), nil, seed)
	if err != nil {
		panic(err)
	}

	var kvs []keyValue
	for i := 0; i < n; i++ {
		v := make([]byte, 64)
		_, _ = drbg.Read(v)
		kvs = append(kvs, keyValue{
			Key:   api.HashStorageKey(v),
			Value: v,
		})
	}

	return kvs
}
