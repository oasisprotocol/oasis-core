package cachingclient

import (
	"context"
	"crypto"
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/memory"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

const cacheSize = 10

// TODO: Update this test stub after implementing caching of MKVS ops.
// Should be implemented as part of
// https://github.com/oasislabs/ekiden/issues/1664.
func TestSingleAndPersistence(t *testing.T) {
	var err error

	var sk signature.PrivateKey
	sk, err = signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "failed to generate dummy receipt signing key")
	remote := memory.New(&sk)
	client, cacheDir := requireNewClient(t, remote)
	defer func() {
		os.RemoveAll(cacheDir)
	}()

	wl := makeTestWriteLog([]byte("TestSingle"), cacheSize)
	expectedNewRoot := tests.CalculateExpectedNewRoot(t, wl)

	var root hash.Hash
	root.Empty()
	receipts, err := client.Apply(context.Background(), root, expectedNewRoot, wl)
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	var receiptBody api.MKVSReceiptBody
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}

	// TODO: Check if retrieving values from MKVS uses cache.

	// Test the persistence.
	client.Cleanup()
	remote = memory.New(&sk)
	_, err = New(remote)
	require.NoError(t, err, "New - reopen")

	// TODO: Check if retrieving values from MKVS uses cache.
}

// TODO: Update this test after implementing caching of MKVS ops.
// Should be implemented as part of
// https://github.com/oasislabs/ekiden/issues/1664.
// func TestBatch(t *testing.T) {
// 	remote := memory.New(mock.New(), nil)
// 	client, cacheDir := requireNewClient(t, remote)
// 	defer func() {
// 		client.Cleanup()
// 		os.RemoveAll(cacheDir)
// 	}()

// 	kvs := makeTestKeyValues([]byte("TestBatch"), cacheSize)
// 	var (
// 		ks []api.Key
// 		vs []api.Value
// 	)
// 	for _, v := range kvs {
// 		vs = append(vs, api.Value{
// 			Data:       v.Value,
// 			Expiration: 666,
// 		})
// 		ks = append(ks, v.Key)
// 	}

// 	err := client.InsertBatch(context.Background(), vs, api.InsertOptions{LocalOnly: false})
// 	require.NoError(t, err, "InsertBatch")

// 	values, err := client.GetBatch(context.Background(), ks)
// 	require.NoError(t, err, "GetBatch")
// 	for i, v := range values {
// 		require.EqualValues(t, kvs[i].Value, v, "GetBatch - value: %d", i)
// 	}
// }

//

func requireNewClient(t *testing.T, remote api.Backend) (api.Backend, string) {
	<-remote.Initialized()
	cacheDir, err := ioutil.TempDir("", "ekiden-cachingclient-test_")
	require.NoError(t, err, "create cache dir")

	viper.Set(cfgCacheFile, filepath.Join(cacheDir, "db"))
	viper.Set(cfgCacheSize, 1024768)

	client, err := New(remote)
	if err != nil {
		os.RemoveAll(cacheDir)
	}
	require.NoError(t, err, "New")

	return client, cacheDir
}

// TODO: Update these commented helper functions as part of
// https://github.com/oasislabs/ekiden/issues/1664.

// func requireGet(t *testing.T, client api.Backend, key api.Key, expected []byte) bool {
// 	mkvsReceipt, err := client.Get(context.Background(), key)
// 	switch value {
// 	case nil:
// 		require.Error(t, err, "Get(miss)")
// 		require.Equal(t, api.ErrKeyNotFound, err, "Get(miss) error is ErrKeyNotFound")
// 		return false
// 	default:
// 		require.NoError(t, err, "Get(hit)")
// 		require.EqualValues(t, expected, value, "Get() returned expected value")
// 		return true
// 	}
// }

// func requireKVs(t *testing.T, client api.Backend, kvs []keyValue, expectedHits int) {
// 	var valuesInCache int
// 	for _, v := range kvs {
// 		if requireGet(t, client, v.Key, v.Value) {
// 			valuesInCache++
// 		}
// 	}
// 	require.Equal(t, expectedHits, valuesInCache, "Cache has expected number of entries")
// }

func makeTestWriteLog(seed []byte, n int) api.WriteLog {
	h := crypto.SHA512.New()
	_, _ = h.Write(seed)
	drbg, err := drbg.New(crypto.SHA256, h.Sum(nil), nil, seed)
	if err != nil {
		panic(err)
	}

	var wl api.WriteLog
	for i := 0; i < n; i++ {
		v := make([]byte, 64)
		_, _ = drbg.Read(v)
		wl = append(wl, api.LogEntry{
			Key:   []byte(strconv.Itoa(i)),
			Value: v,
		})
	}

	return wl
}
