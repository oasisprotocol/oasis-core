package transaction

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

func TestTransaction(t *testing.T) {
	ctx := context.Background()
	store := mkvs.New(nil, nil, node.RootTypeState)

	var emptyRoot node.Root
	emptyRoot.Type = node.RootTypeState
	emptyRoot.Empty()

	tree := NewTree(store, emptyRoot)

	// No transactions in empty tree.
	txns, err := tree.GetTransactions(ctx)
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txns, 0, "empty tree should have no transactions")

	// Add transaction.
	tx := Transaction{
		Input:      []byte("this goes in"),
		Output:     []byte("and this comes out"),
		BatchOrder: 0,
	}
	tags := Tags{
		Tag{Key: []byte("tag1"), Value: []byte("value1")},
	}
	err = tree.AddTransaction(ctx, tx, tags)
	require.NoError(t, err, "AddTransaction")

	// There should be a transaction now.
	txns, err = tree.GetTransactions(ctx)
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txns, 1, "there should be one transaction")

	txHash := hash.NewFromBytes(tx.Input)

	require.True(t, txns[0].Equal(&tx), "transaction should have correct artifacts")

	// Add some more transactions.
	var testTxns []Transaction
	for i := 0; i < 20; i++ {
		newTx := Transaction{
			Input:      []byte(fmt.Sprintf("this goes in (%d)", i)),
			Output:     []byte("and this comes out"),
			BatchOrder: uint32(i + 1),
		}
		newTags := Tags{
			Tag{Key: []byte("tagA"), Value: []byte("valueA")},
			Tag{Key: []byte("tagB"), Value: []byte("valueB")},
		}
		err = tree.AddTransaction(ctx, newTx, newTags)
		require.NoError(t, err, "AddTransaction")
		testTxns = append(testTxns, newTx)
	}

	txns, err = tree.GetTransactions(ctx)
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txns, len(testTxns)+1, "there should be some transactions")

	var txHashes []hash.Hash
	txnsByHash := make(map[hash.Hash]*Transaction)
	for i, tx := range txns {
		txnsByHash[tx.Hash()] = tx
		txHashes = append(txHashes, tx.Hash())

		// Make sure the transactions are returned in batch order.
		if i > 0 {
			require.EqualValues(t, testTxns[i-1], *tx, "transactions must be returned in batch order")
		}
	}

	for _, checkTx := range testTxns {
		require.Contains(t, txnsByHash, checkTx.Hash(), "transaction should exist")
		require.True(t, txnsByHash[checkTx.Hash()].Equal(&checkTx), "transaction should have the correct artifacts") // nolint: gosec
	}

	// Fetching a single transaction should work.
	rtx, err := tree.GetTransaction(ctx, txHash)
	require.NoError(t, err, "GetTransaction")
	require.True(t, rtx.Equal(&tx), "transaction should have correct artifacts")

	missingHash := hash.NewFromBytes([]byte("this transaction does not exist"))

	_, err = tree.GetTransaction(ctx, missingHash)
	require.Error(t, err, "GetTransaction")
	require.Equal(t, err, ErrNotFound, "GetTransaction should return ErrNotFound on missing tx")

	// Fetching multiple transactions should work.
	queryTxHashes := append([]hash.Hash{missingHash}, txHashes[:5]...)
	matches, err := tree.GetTransactionMultiple(ctx, queryTxHashes)
	require.NoError(t, err, "GetTransactionMultiple")
	require.Len(t, matches, 5, "all matched transactions should be returned")

	// Get tags.
	rtags, err := tree.GetTags(ctx)
	require.NoError(t, err, "GetTags")
	require.Len(t, rtags, 1+len(testTxns)*2, "all emitted tags should be there")

	tagsByTxn := make(map[hash.Hash]Tags)
	for _, tag := range rtags {
		txTags := tagsByTxn[tag.TxHash]
		txTags = append(txTags, tag)
		tagsByTxn[tag.TxHash] = txTags
	}

	for _, checkTx := range testTxns {
		require.Contains(t, tagsByTxn, checkTx.Hash(), "tags should exist")
		require.Contains(t, tagsByTxn[checkTx.Hash()], Tag{Key: []byte("tagA"), Value: []byte("valueA"), TxHash: checkTx.Hash()})
		require.Contains(t, tagsByTxn[checkTx.Hash()], Tag{Key: []byte("tagB"), Value: []byte("valueB"), TxHash: checkTx.Hash()})
	}

	// Get input batch.
	batch, err := tree.GetInputBatch(ctx, 0, 0)
	require.NoError(t, err, "GetInputBatch")
	require.Len(t, batch, len(testTxns)+1, "batch should have the same transactions")
	require.EqualValues(t, tx.Input, batch[0], "input batch transactions must be in correct order")
	for idx, checkTx := range testTxns {
		require.EqualValues(t, checkTx.Input, batch[idx+1], "input batch transactions must be in correct order")
	}

	// Get input batch with size limits.
	_, err = tree.GetInputBatch(ctx, 5, 0)
	require.Error(t, err, "GetInputBatch should fail with too many transactions")
	_, err = tree.GetInputBatch(ctx, 0, 64)
	require.Error(t, err, "GetInputBatch should fail with too large transactions")

	// Commit.
	// NOTE: This root is synced with tests in runtime/src/transaction/tree.rs.
	writeLog, rootHash, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.EqualValues(t, "8399ffa753987b00ec6ab251337c6b88e40812662ed345468fcbf1dbdd16321c", rootHash.String(), "transaction root should be stable")

	// Apply write log to tree and check if everything is still there.
	err = store.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
	require.NoError(t, err, "ApplyWriteLog")
	_, storeRootHash, err := store.Commit(ctx, emptyRoot.Namespace, emptyRoot.Version)
	require.NoError(t, err, "Commit")
	require.EqualValues(t, rootHash, storeRootHash)

	tree = NewTree(store, node.Root{Type: node.RootTypeState, Hash: storeRootHash})
	txns, err = tree.GetTransactions(ctx)
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txns, len(testTxns)+1, "there should be some transactions")

	txnsByHash = make(map[hash.Hash]*Transaction)
	for _, tx := range txns {
		txnsByHash[tx.Hash()] = tx
	}

	for _, checkTx := range testTxns {
		require.Contains(t, txnsByHash, checkTx.Hash(), "transaction should exist")
		require.True(t, txnsByHash[checkTx.Hash()].Equal(&checkTx), "transaction should have the correct artifacts") // nolint: gosec
	}
}

func TestTransactionInvalidBatchOrder(t *testing.T) {
	ctx := context.Background()
	store := mkvs.New(nil, nil, node.RootTypeState)

	var emptyRoot node.Root
	emptyRoot.Empty()

	tree := NewTree(store, emptyRoot)

	tx := Transaction{
		Input:      []byte("this goes in"),
		Output:     []byte("and this comes out"),
		BatchOrder: 1, // Invalid batch order as the first transaction should be at index zero.
	}
	err := tree.AddTransaction(ctx, tx, nil)
	require.NoError(t, err, "AddTransaction")

	_, err = tree.GetInputBatch(ctx, 0, 0)
	require.Error(t, err, "GetInputBatch should fail with inconsistent order")
}

func TestIOWriteLogValidation(t *testing.T) {
	var (
		err  error
		hash hash.Hash
	)

	hash.Empty()

	// Test garbage first.
	err = ValidateIOWriteLog(
		writelog.WriteLog{
			{Key: []byte("malformed key"), Value: []byte("some value")},
		},
		1024,
		1024,
	)
	require.EqualError(t, err, "transaction: invalid key format")

	garbledArtifact := txnKeyFmt.Encode(&hash)
	garbledArtifact = append(garbledArtifact, uint8(42))
	err = ValidateIOWriteLog(
		writelog.WriteLog{
			{Key: garbledArtifact, Value: []byte("some value")},
		},
		1024,
		1024,
	)
	require.Error(t, err, "Decoding an invalid artifact type should fail")

	err = ValidateIOWriteLog(
		writelog.WriteLog{
			{Key: txnKeyFmt.Encode(&hash, kindInput), Value: []byte("some value")},
			{Key: tagKeyFmt.Encode([]byte("tag"), &hash), Value: []byte("some value")},
		},
		1024,
		1024,
	)
	require.NoError(t, err, "All writelog keys should be valid")

	// Test limits.
	cases := []struct {
		inputs, outputs   int
		maxCount, maxSize uint64
		expectedError     string
	}{
		// Overflow artifact count.
		{2, 2, 2, 1024, ""},
		{3, 2, 2, 1024, "transaction: too many inputs or outputs"},
		{2, 3, 2, 1024, "transaction: too many inputs or outputs"},

		// Overflow total input size
		{1, 0, 10, 64, ""},
		{10, 0, 10, 64, "transaction: input set size exceeds configuration"},
	}

	for num, c := range cases {
		wl := writelog.WriteLog{}
		for kind, cnt := range map[artifactKind]int{
			kindInput:  c.inputs,
			kindOutput: c.outputs,
		} {
			for i := 0; i < cnt; i++ {
				wl = append(wl, writelog.LogEntry{
					Key:   txnKeyFmt.Encode(&hash, kind),
					Value: []byte("some long-ish value"),
				})
			}
		}

		err = ValidateIOWriteLog(wl, c.maxCount, c.maxSize)
		if len(c.expectedError) > 0 {
			require.EqualError(t, err, c.expectedError, fmt.Sprintf("bulk case %d", num))
		} else {
			require.NoError(t, err, fmt.Sprintf("bulk case %d", num))
		}
	}
}
