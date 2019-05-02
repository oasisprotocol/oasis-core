package indexer

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/runtime"
)

func testOperations(t *testing.T, backend Backend) {
	ctx := context.Background()

	var id signature.PublicKey
	_ = id.UnmarshalBinary(make([]byte, signature.PublicKeySize))

	err := backend.Index(id, 42, []runtime.Tag{
		runtime.Tag{TxnIndex: runtime.TagTxnIndexBlock, Key: []byte("key"), Value: []byte("value")},
		runtime.Tag{TxnIndex: runtime.TagTxnIndexBlock, Key: []byte("key2"), Value: []byte("value2")},
		runtime.Tag{TxnIndex: 0, Key: []byte("hello"), Value: []byte("world")},
		runtime.Tag{TxnIndex: 0, Key: []byte("some"), Value: []byte("world")},
		runtime.Tag{TxnIndex: 1, Key: []byte("hello"), Value: []byte("world")},
	})
	require.NoError(t, err, "Index")

	_, err = backend.QueryBlock(ctx, id, []byte("key"), []byte("invalid"))
	require.Equal(t, ErrNotFound, err, "QueryBlock must return a not found error")

	round, err := backend.QueryBlock(ctx, id, []byte("key"), []byte("value"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 42, round)

	_, err = backend.QueryBlock(ctx, id, []byte("key"), []byte("value1"))
	require.Equal(t, ErrNotFound, err, "QueryBlock must return a not found error")

	round, err = backend.QueryBlock(ctx, id, []byte("key2"), []byte("value2"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 42, round)

	_, err = backend.QueryBlock(ctx, id, []byte("hello"), []byte("world"))
	require.Equal(t, ErrNotFound, err, "QueryBlock must return a not found error")

	_, _, err = backend.QueryTxn(ctx, id, []byte("key"), []byte("value"))
	require.Equal(t, ErrNotFound, err, "QueryTxn must return a not found error")

	_, _, err = backend.QueryTxn(ctx, id, []byte("key2"), []byte("value2"))
	require.Equal(t, ErrNotFound, err, "QueryTxn must return a not found error")

	round, txnIdx, err := backend.QueryTxn(ctx, id, []byte("hello"), []byte("world"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 42, round)
	require.True(t, txnIdx == 0 || txnIdx == 1)

	round, txnIdx, err = backend.QueryTxn(ctx, id, []byte("some"), []byte("world"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 42, round)
	require.EqualValues(t, 0, txnIdx)

	err = backend.Index(id, 43, []runtime.Tag{
		runtime.Tag{TxnIndex: runtime.TagTxnIndexBlock, Key: []byte("key"), Value: []byte("value1")},
		runtime.Tag{TxnIndex: 5, Key: []byte("foo"), Value: []byte("bar")},
	})
	require.NoError(t, err, "Index")

	round, err = backend.QueryBlock(ctx, id, []byte("key"), []byte("value1"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 43, round)

	round, txnIdx, err = backend.QueryTxn(ctx, id, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 43, round)
	require.EqualValues(t, 5, txnIdx)

	round, err = backend.QueryBlock(ctx, id, []byte("key2"), []byte("value2"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 42, round)

	// Test advanced transaction queries.
	roundMin := uint64(40)
	roundMax := uint64(50)
	query := Query{
		RoundMin: &roundMin,
		RoundMax: &roundMax,
		Conditions: []Condition{
			Condition{Key: []byte("hello"), Values: [][]byte{[]byte("world")}},
		},
	}
	results, err := backend.QueryTxns(ctx, id, query)
	if err != ErrUnsupported {
		// Ignore for backends that don't support QueryTxns.
		require.NoError(t, err, "QueryTxns")
		require.Len(t, results, 1)
		require.Contains(t, results, uint64(42))
		require.Len(t, results[42], 2)
		require.Contains(t, results[42], int32(0))
		require.Contains(t, results[42], int32(1))
	}

	query = Query{
		Conditions: []Condition{
			Condition{Key: []byte("hello"), Values: [][]byte{[]byte("worlx"), []byte("world")}},
		},
	}
	results, err = backend.QueryTxns(ctx, id, query)
	if err != ErrUnsupported {
		// Ignore for backends that don't support QueryTxns.
		require.NoError(t, err, "QueryTxns")
		require.NoError(t, err, "QueryTxns")
		require.Len(t, results, 1)
		require.Contains(t, results, uint64(42))
		require.Len(t, results[42], 2)
		require.Contains(t, results[42], int32(0))
		require.Contains(t, results[42], int32(1))
	}
}

func testLoadIndex(t *testing.T, backend Backend) {
	ctx := context.Background()

	var id signature.PublicKey
	_ = id.UnmarshalBinary(make([]byte, signature.PublicKeySize))

	round, err := backend.QueryBlock(ctx, id, []byte("key"), []byte("value"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 42, round)
}

func testBackend(t *testing.T, factory func(string) (Backend, error)) {
	// Create a new random temporary directory under /tmp.
	dataDir, err := ioutil.TempDir("", "ekiden-client-indexer-test_")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dataDir)

	t.Run("Operations", func(t *testing.T) {
		var backend Backend
		backend, err = factory(dataDir)
		require.NoError(t, err, "New")
		defer backend.Stop()

		testOperations(t, backend)
	})
	t.Run("LoadIndex", func(t *testing.T) {
		var backend Backend
		backend, err = factory(dataDir)
		require.NoError(t, err, "New")
		defer backend.Stop()

		testLoadIndex(t, backend)
	})
}

func TestExactBackend(t *testing.T) {
	testBackend(t, NewExactBackend)
}

func TestBleveBackend(t *testing.T) {
	testBackend(t, NewBleveBackend)
}
