package tagindexer

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/runtime/client/api"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
)

func testOperations(t *testing.T, backend Backend) {
	ctx := context.Background()

	tx1 := []byte("i am a transaction")
	tx2 := []byte("i am a second transaction")
	tx3 := []byte("i am a third transaction")

	var tx1Hash, tx2Hash, tx3Hash hash.Hash
	tx1Hash.FromBytes(tx1)
	tx2Hash.FromBytes(tx2)
	tx3Hash.FromBytes(tx3)

	var blockHash1 hash.Hash
	blockHash1.FromBytes([]byte("this is a fake block hash 1"))

	err := backend.Index(
		ctx,
		42,
		blockHash1,
		// Transactions.
		[]*transaction.Transaction{
			&transaction.Transaction{Input: tx1, Output: tx1},
			&transaction.Transaction{Input: tx2, Output: tx2},
		},
		// Tags.
		transaction.Tags{
			transaction.Tag{Key: []byte("hello"), Value: []byte("world"), TxHash: tx1Hash},
			transaction.Tag{Key: []byte("some"), Value: []byte("world"), TxHash: tx1Hash},
			transaction.Tag{Key: []byte("hello"), Value: []byte("world"), TxHash: tx2Hash},
			transaction.Tag{Key: []byte("hello2"), Value: []byte("world"), TxHash: tx2Hash},
		},
	)
	require.NoError(t, err, "Index")

	err = backend.WaitBlockIndexed(ctx, 41)
	require.NoError(t, err, "WaitBlockIndexed")
	err = backend.WaitBlockIndexed(ctx, 42)
	require.NoError(t, err, "WaitBlockIndexed")

	var invalidBlockHash hash.Hash
	_, err = backend.QueryBlock(ctx, invalidBlockHash)
	require.Equal(t, api.ErrNotFound, err, "QueryBlock must return a not found error")

	round, err := backend.QueryBlock(ctx, blockHash1)
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 42, round)

	_, _, _, err = backend.QueryTxn(ctx, []byte("key"), []byte("value"))
	require.Equal(t, api.ErrNotFound, err, "QueryTxn must return a not found error")

	_, _, _, err = backend.QueryTxn(ctx, []byte("key2"), []byte("value2"))
	require.Equal(t, api.ErrNotFound, err, "QueryTxn must return a not found error")

	round, txnHash, txnIndex, err := backend.QueryTxn(ctx, []byte("hello2"), []byte("world"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 42, round)
	require.EqualValues(t, tx2Hash, txnHash)
	require.EqualValues(t, 1, txnIndex)

	round, txnHash, txnIndex, err = backend.QueryTxn(ctx, []byte("some"), []byte("world"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 42, round)
	require.EqualValues(t, tx1Hash, txnHash)
	require.EqualValues(t, 0, txnIndex)

	txnHash, err = backend.QueryTxnByIndex(ctx, 42, 0)
	require.NoError(t, err, "QueryTxnByIndex")
	require.EqualValues(t, tx1Hash, txnHash)

	txnHash, err = backend.QueryTxnByIndex(ctx, 42, 1)
	require.NoError(t, err, "QueryTxnByIndex")
	require.EqualValues(t, tx2Hash, txnHash)

	var blockHash2 hash.Hash
	blockHash2.FromBytes([]byte("this is a fake block hash 2"))

	err = backend.Index(
		ctx,
		43,
		blockHash2,
		// Transactions.
		[]*transaction.Transaction{
			&transaction.Transaction{Input: tx3, Output: tx3},
		},
		// Tags.
		transaction.Tags{
			transaction.Tag{Key: []byte("foo"), Value: []byte("bar"), TxHash: tx3Hash},
		},
	)
	require.NoError(t, err, "Index")

	round, err = backend.QueryBlock(ctx, blockHash2)
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 43, round)

	round, txnHash, txnIndex, err = backend.QueryTxn(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 43, round)
	require.EqualValues(t, tx3Hash, txnHash)
	require.EqualValues(t, 0, txnIndex)

	round, err = backend.QueryBlock(ctx, blockHash1)
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 42, round)

	// Test advanced transaction queries.
	query := api.Query{
		RoundMin: 40,
		RoundMax: 50,
		Conditions: []api.QueryCondition{
			api.QueryCondition{Key: []byte("hello"), Values: [][]byte{[]byte("world")}},
		},
	}
	results, err := backend.QueryTxns(ctx, query)
	require.NoError(t, err, "QueryTxns")
	require.Len(t, results, 1)
	require.Contains(t, results, uint64(42))
	require.Len(t, results[42], 2)
	require.Contains(t, results[42], Result{TxHash: tx1Hash, TxIndex: 0})
	require.Contains(t, results[42], Result{TxHash: tx2Hash, TxIndex: 1})

	query = api.Query{
		Conditions: []api.QueryCondition{
			api.QueryCondition{Key: []byte("hello"), Values: [][]byte{[]byte("worlx"), []byte("world")}},
		},
	}
	results, err = backend.QueryTxns(ctx, query)
	require.NoError(t, err, "QueryTxns")
	require.NoError(t, err, "QueryTxns")
	require.Len(t, results, 1)
	require.Contains(t, results, uint64(42))
	require.Len(t, results[42], 2)
	require.Contains(t, results[42], Result{TxHash: tx1Hash, TxIndex: 0})
	require.Contains(t, results[42], Result{TxHash: tx2Hash, TxIndex: 1})
}

func testLoadIndex(t *testing.T, backend Backend) {
	ctx := context.Background()

	err := backend.WaitBlockIndexed(ctx, 42)
	require.NoError(t, err, "WaitBlockIndexed")

	var blockHash1 hash.Hash
	blockHash1.FromBytes([]byte("this is a fake block hash 1"))

	round, err := backend.QueryBlock(ctx, blockHash1)
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 42, round)
}

func testBackend(t *testing.T, factory BackendFactory) {
	// Create a new random temporary directory under /tmp.
	dataDir, err := ioutil.TempDir("", "oasis-client-indexer-test_")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dataDir)

	var id common.Namespace

	t.Run("Operations", func(t *testing.T) {
		var backend Backend
		backend, err = factory(dataDir, id)
		require.NoError(t, err, "New")
		defer backend.Close()

		testOperations(t, backend)
	})
	t.Run("LoadIndex", func(t *testing.T) {
		var backend Backend
		backend, err = factory(dataDir, id)
		require.NoError(t, err, "New")
		defer backend.Close()

		testLoadIndex(t, backend)
	})
}

func TestBleveBackend(t *testing.T) {
	testBackend(t, NewBleveBackend())
}
