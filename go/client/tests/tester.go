// Package tests is a collection of client interface test cases.
package tests

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/client"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
)

// Keep this above the test network's max batch timeout.
const timeout = 2 * time.Second

// ClientImplementationTests runs the client interface implementation tests.
func ClientImplementationTests(
	t *testing.T,
	client *client.Client,
	runtimeID signature.PublicKey,
) {
	t.Run("SubmitTx", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		testSubmitTransaction(ctx, t, runtimeID, client)
	})

	t.Run("Query", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		testQuery(ctx, t, runtimeID, client)
	})

	// These can't test anything useful, so just make sure the roundtrip works.
	t.Run("WaitSync", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		err := client.WaitSync(ctx)
		require.NoError(t, err, "WaitSync")
	})
	t.Run("IsSynced", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		synced, err := client.IsSynced(ctx)
		require.NoError(t, err, "IsSynced")
		require.EqualValues(t, synced, true)
	})
}

func testSubmitTransaction(
	ctx context.Context,
	t *testing.T,
	runtimeID signature.PublicKey,
	c *client.Client,
) {
	// Submit a test transaction.
	testInput := []byte("octopus")
	testOutput, err := c.SubmitTx(ctx, testInput, runtimeID)

	// Check if everything is in order.
	require.NoError(t, err, "SubmitTx")
	require.EqualValues(t, testInput, testOutput)
}

func testQuery(
	ctx context.Context,
	t *testing.T,
	runtimeID signature.PublicKey,
	c *client.Client,
) {
	err := c.WaitBlockIndexed(ctx, runtimeID, 4)
	require.NoError(t, err, "WaitBlockIndexed")

	// Based on SubmitTx and the mock worker.
	testInput := []byte("octopus")
	testOutput := testInput

	// Fetch blocks.
	blk, err := c.GetBlock(ctx, runtimeID, 1)
	// Epoch transition from TestNode/ComputeWorker/InitialEpochTransition
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 1, blk.Header.Round)

	blk, err = c.GetBlock(ctx, runtimeID, 2)
	// Epoch transition from TestNode/TransactionSchedulerWorker/InitialEpochTransition
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 2, blk.Header.Round)

	// Normal block from TestNode/TransactionSchedulerWorker/QueueCall

	blk, err = c.GetBlock(ctx, runtimeID, 0xffffffffffffffff)
	// Normal block from TestNode/Client/SubmitTx
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 4, blk.Header.Round)

	// Out of bounds block round.
	_, err = c.GetBlock(ctx, runtimeID, 5)
	require.Error(t, err, "GetBlock")

	// Fetch transaction.
	tx, err := c.GetTxn(ctx, runtimeID, 4, 0)
	require.NoError(t, err, "GetTxn(0)")
	require.EqualValues(t, 4, tx.Block.Header.Round)
	require.EqualValues(t, testInput, tx.Input)
	require.EqualValues(t, testOutput, tx.Output)

	// Out of bounds transaction index.
	_, err = c.GetTxn(ctx, runtimeID, 4, 1)
	require.Error(t, err, "GetTxn(1)")

	// Get transaction by block hash and index.
	tx, err = c.GetTxnByBlockHash(ctx, runtimeID, blk.Header.EncodedHash(), 0)
	require.NoError(t, err, "GetTxnByBlockHash")
	require.EqualValues(t, 4, tx.Block.Header.Round)
	require.EqualValues(t, testInput, tx.Input)
	require.EqualValues(t, testOutput, tx.Output)

	// Invalid block hash.
	var invalidHash hash.Hash
	invalidHash.Empty()
	_, err = c.GetTxnByBlockHash(ctx, runtimeID, invalidHash, 0)
	require.Error(t, err, "GetTxnByBlockHash(invalid)")

	// Check that indexer has indexed block keys (check the mock worker for key/values).
	blk, err = c.QueryBlock(ctx, runtimeID, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 3, blk.Header.Round)

	// Check that indexer has indexed txn keys (check the mock worker for key/values).
	tx, err = c.QueryTxn(ctx, runtimeID, []byte("txn_foo"), []byte("txn_bar"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 3, tx.Block.Header.Round)
	require.EqualValues(t, 0, tx.Index)
	// Check for values from TestNode/TransactionSchedulerWorker/QueueCall
	require.EqualValues(t, []byte("hello world"), tx.Input)
	require.EqualValues(t, []byte("hello world"), tx.Output)

	// Transactions (check the mock worker for content).
	txns, err := c.GetTransactions(ctx, runtimeID, blk.Header.Round, blk.Header.IORoot)
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txns, 1)
	// Check for values from TestNode/TransactionSchedulerWorker/QueueCall
	require.EqualValues(t, []byte("hello world"), txns[0])

	// Test advanced transaction queries.
	query := client.Query{
		RoundMin: 0,
		RoundMax: 4,
		Conditions: []client.QueryCondition{
			client.QueryCondition{Key: []byte("txn_foo"), Values: [][]byte{[]byte("txn_bar")}},
		},
	}
	results, err := c.QueryTxns(ctx, runtimeID, query)
	require.NoError(t, err, "QueryTxns")
	// One from TestNode/TransactionSchedulerWorker/QueueCall, one from TestNode/Client/SubmitTx
	require.Len(t, results, 2)
	sort.Slice(results, func(i, j int) bool {
		return bytes.Compare(results[i].Input, results[j].Input) < 0
	})
	require.EqualValues(t, 3, results[0].Block.Header.Round)
	require.EqualValues(t, 0, results[0].Index)
	// Check for values from TestNode/TransactionSchedulerWorker/QueueCall
	require.EqualValues(t, []byte("hello world"), results[0].Input)
	require.EqualValues(t, []byte("hello world"), results[0].Output)
}
