package transaction

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

func TestTransaction(t *testing.T) {
	ctx := context.Background()
	store := urkel.New(nil, nil)

	var emptyRoot node.Root
	emptyRoot.Empty()

	tree, err := NewTree(ctx, store, emptyRoot)
	require.NoError(t, err, "NewTree")

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

	var txHash hash.Hash
	txHash.FromBytes(tx.Input)

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

	txnsByHash := make(map[hash.Hash]*Transaction)
	for _, tx := range txns {
		txnsByHash[tx.Hash()] = tx
	}

	for _, checkTx := range testTxns {
		require.Contains(t, txnsByHash, checkTx.Hash(), "transaction should exist")
		require.True(t, txnsByHash[checkTx.Hash()].Equal(&checkTx), "transaction should have the correct artifacts")
	}

	// Fetching a single transaction should work.
	rtx, err := tree.GetTransaction(ctx, txHash)
	require.NoError(t, err, "GetTransaction")
	require.True(t, rtx.Equal(&tx), "transaction should have correct artifacts")

	var missingHash hash.Hash
	missingHash.FromBytes([]byte("this transaction does not exist"))

	_, err = tree.GetTransaction(ctx, missingHash)
	require.Error(t, err, "GetTransaction")
	require.Equal(t, err, ErrNotFound, "GetTransaction should return ErrNotFound on missing tx")

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
	batch, err := tree.GetInputBatch(ctx)
	require.NoError(t, err, "GetInputBatch")
	require.Len(t, batch, len(testTxns)+1, "batch should have the same transactions")
	require.EqualValues(t, tx.Input, batch[0], "input batch transactions must be in correct order")
	for idx, checkTx := range testTxns {
		require.EqualValues(t, checkTx.Input, batch[idx+1], "input batch transactions must be in correct order")
	}

	// Commit.
	// NOTE: This root is synced with tests in runtime/src/transaction/tree.rs.
	writeLog, rootHash, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.EqualValues(t, "a4d8f91eb389f897f031c1bb996380a23071ac0797c01ee346b86d3e2307f105", rootHash.String(), "transaction root should be stable")

	// Apply write log to tree and check if everything is still there.
	err = store.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
	require.NoError(t, err, "ApplyWriteLog")
	_, storeRootHash, err := store.Commit(ctx, emptyRoot.Namespace, emptyRoot.Round)
	require.NoError(t, err, "Commit")
	require.EqualValues(t, rootHash, storeRootHash)

	tree, err = NewTree(ctx, store, node.Root{Hash: storeRootHash})
	require.NoError(t, err, "NewTree")

	txns, err = tree.GetTransactions(ctx)
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txns, len(testTxns)+1, "there should be some transactions")

	txnsByHash = make(map[hash.Hash]*Transaction)
	for _, tx := range txns {
		txnsByHash[tx.Hash()] = tx
	}

	for _, checkTx := range testTxns {
		require.Contains(t, txnsByHash, checkTx.Hash(), "transaction should exist")
		require.True(t, txnsByHash[checkTx.Hash()].Equal(&checkTx), "transaction should have the correct artifacts")
	}
}
