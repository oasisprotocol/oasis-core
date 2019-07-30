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

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/drbg"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/leveldb"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/tests"
)

var testNs common.Namespace

const cacheSize = 10

func TestCachingClient(t *testing.T) {
	signer, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "failed to generate dummy receipt signing key")
	dbDir, err := ioutil.TempDir("", "cachingclient.test.leveldb")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dbDir)
	remote, err := leveldb.New(dbDir, signer, 0, false)
	require.NoError(t, err, "leveldb.New")

	client, cacheDir := requireNewClient(t, remote)
	defer os.RemoveAll(cacheDir)

	wl := makeTestWriteLog([]byte("TestSingle"), cacheSize)
	expectedNewRoot := tests.CalculateExpectedNewRoot(t, wl, testNs, 1)

	var root hash.Hash
	root.Empty()
	receipts, err := client.Apply(context.Background(), testNs, 0, root, 1, expectedNewRoot, wl)
	require.NoError(t, err, "Apply() should not return an error")
	require.NotNil(t, receipts, "Apply() should return receipts")

	// Check the receipts and ensure they contain a new root that equals the
	// expected new root.
	var receiptBody api.ReceiptBody
	for _, receipt := range receipts {
		err = receipt.Open(&receiptBody)
		require.NoError(t, err, "receipt.Open() should not return an error")
		require.Equal(t, testNs, receiptBody.Namespace, "receiptBody should contain correct namespace")
		require.EqualValues(t, 1, receiptBody.Round, "receiptBody should contain correct round")
		require.Equal(t, 1, len(receiptBody.Roots), "receiptBody should contain 1 root")
		require.EqualValues(t, expectedNewRoot, receiptBody.Roots[0], "receiptBody root should equal the expected new root")
	}

	// Check if the values match.
	r := node.Root{
		Namespace: testNs,
		Round:     1,
		Hash:      expectedNewRoot,
	}
	tree, err := urkel.NewWithRoot(context.Background(), client, nil, r)
	require.NoError(t, err, "NewWithRoot")
	for i, kv := range wl {
		var v []byte
		v, err = tree.Get(context.Background(), kv.Key)
		require.NoError(t, err, "Get1")
		require.EqualValues(t, kv.Value, v, "Get1 - value: %d", i)
	}

	// Test the persistence.
	client.Cleanup()
	dbDir, err = ioutil.TempDir("", "cachingclient.test.leveldb")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dbDir)
	remote, err = leveldb.New(dbDir, signer, 0, false)
	require.NoError(t, err, "leveldb.New")
	_, err = New(remote, false)
	require.NoError(t, err, "New - reopen")

	// Check if the values are still fetchable.
	tree, err = urkel.NewWithRoot(context.Background(), client, nil, r)
	require.NoError(t, err, "NewWithRoot")
	for i, kv := range wl {
		var v []byte
		v, err = tree.Get(context.Background(), kv.Key)
		require.NoError(t, err, "Get2")
		require.EqualValues(t, kv.Value, v, "Get2 - value: %d", i)
	}
}

func requireNewClient(t *testing.T, remote api.Backend) (api.Backend, string) {
	<-remote.Initialized()
	cacheDir, err := ioutil.TempDir("", "ekiden-cachingclient-test_")
	require.NoError(t, err, "create cache dir")

	viper.Set(cfgCacheFile, filepath.Join(cacheDir, "db"))
	viper.Set(cfgCacheSize, 1024768)

	client, err := New(remote, false)
	if err != nil {
		os.RemoveAll(cacheDir)
	}
	require.NoError(t, err, "New")

	return client, cacheDir
}

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

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("ekiden storage cachingclient test ns"))
	copy(testNs[:], ns[:])
}
