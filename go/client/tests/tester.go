// Package tests is a collection of client interface test cases.
package tests

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/client/api"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

// Keep this above the test network's max batch timeout.
const timeout = 2 * time.Second

// ClientImplementationTests runs the client interface implementation tests.
func ClientImplementationTests(
	t *testing.T,
	client api.RuntimeClient,
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
}

func testSubmitTransaction(
	ctx context.Context,
	t *testing.T,
	runtimeID signature.PublicKey,
	c api.RuntimeClient,
) {
	// Submit a test transaction.
	testInput := []byte("octopus")
	testOutput, err := c.SubmitTx(ctx, &api.SubmitTxRequest{Data: testInput, RuntimeID: runtimeID})

	// Check if everything is in order.
	require.NoError(t, err, "SubmitTx")
	require.EqualValues(t, testInput, testOutput)
}

func testQuery(
	ctx context.Context,
	t *testing.T,
	runtimeID signature.PublicKey,
	c api.RuntimeClient,
) {
	err := c.WaitBlockIndexed(ctx, &api.WaitBlockIndexedRequest{RuntimeID: runtimeID, Round: 4})
	require.NoError(t, err, "WaitBlockIndexed")

	// Based on SubmitTx and the mock worker.
	testInput := []byte("octopus")
	testOutput := testInput

	// Fetch blocks.
	blk, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: 1})
	// Epoch transition from TestNode/ComputeWorker/InitialEpochTransition
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 1, blk.Header.Round)

	blk, err = c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: 2})
	// Epoch transition from TestNode/TransactionSchedulerWorker/InitialEpochTransition
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 2, blk.Header.Round)

	// Normal block from TestNode/TransactionSchedulerWorker/QueueCall

	blk, err = c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: 0xffffffffffffffff})
	// Normal block from TestNode/Client/SubmitTx
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 4, blk.Header.Round)

	// Out of bounds block round.
	_, err = c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: 5})
	require.Error(t, err, "GetBlock")

	// Fetch transaction.
	tx, err := c.GetTx(ctx, &api.GetTxRequest{RuntimeID: runtimeID, Round: 4, Index: 0})
	require.NoError(t, err, "GetTx(0)")
	require.EqualValues(t, 4, tx.Block.Header.Round)
	require.EqualValues(t, testInput, tx.Input)
	require.EqualValues(t, testOutput, tx.Output)

	// Out of bounds transaction index.
	_, err = c.GetTx(ctx, &api.GetTxRequest{RuntimeID: runtimeID, Round: 4, Index: 1})
	require.Error(t, err, "GetTx(1)")

	// Get transaction by latest round.
	tx, err = c.GetTx(ctx, &api.GetTxRequest{RuntimeID: runtimeID, Round: api.RoundLatest, Index: 0})
	require.NoError(t, err, "GetTx(RoundLatest)")
	require.EqualValues(t, 4, tx.Block.Header.Round)
	require.EqualValues(t, testInput, tx.Input)
	require.EqualValues(t, testOutput, tx.Output)

	// Get transaction by block hash and index.
	tx, err = c.GetTxByBlockHash(ctx, &api.GetTxByBlockHashRequest{RuntimeID: runtimeID, BlockHash: blk.Header.EncodedHash(), Index: 0})
	require.NoError(t, err, "GetTxByBlockHash")
	require.EqualValues(t, 4, tx.Block.Header.Round)
	require.EqualValues(t, testInput, tx.Input)
	require.EqualValues(t, testOutput, tx.Output)

	// Invalid block hash.
	var invalidHash hash.Hash
	invalidHash.Empty()
	_, err = c.GetTxByBlockHash(ctx, &api.GetTxByBlockHashRequest{RuntimeID: runtimeID, BlockHash: invalidHash, Index: 0})
	require.Error(t, err, "GetTxByBlockHash(invalid)")

	// Check that indexer has indexed the block.
	blk, err = c.GetBlockByHash(ctx, &api.GetBlockByHashRequest{RuntimeID: runtimeID, BlockHash: blk.Header.EncodedHash()})
	require.NoError(t, err, "GetBlockByHash")
	require.EqualValues(t, 4, blk.Header.Round)

	// Check that indexer has indexed txn keys (check the mock worker for key/values).
	tx, err = c.QueryTx(ctx, &api.QueryTxRequest{RuntimeID: runtimeID, Key: []byte("txn_foo"), Value: []byte("txn_bar")})
	require.NoError(t, err, "QueryTx")
	require.EqualValues(t, 3, tx.Block.Header.Round)
	require.EqualValues(t, 0, tx.Index)
	// Check for values from TestNode/TransactionSchedulerWorker/QueueCall
	require.EqualValues(t, []byte("hello world"), tx.Input)
	require.EqualValues(t, []byte("hello world"), tx.Output)

	// Transactions (check the mock worker for content).
	txns, err := c.GetTxs(ctx, &api.GetTxsRequest{RuntimeID: runtimeID, Round: blk.Header.Round, IORoot: blk.Header.IORoot})
	require.NoError(t, err, "GetTxs")
	require.Len(t, txns, 1)
	// Check for values from TestNode/Client/SubmitTx
	require.EqualValues(t, []byte("octopus"), txns[0])

	// Test advanced transaction queries.
	query := api.Query{
		RoundMin: 0,
		RoundMax: 4,
		Conditions: []api.QueryCondition{
			api.QueryCondition{Key: []byte("txn_foo"), Values: [][]byte{[]byte("txn_bar")}},
		},
	}
	results, err := c.QueryTxs(ctx, &api.QueryTxsRequest{RuntimeID: runtimeID, Query: query})
	require.NoError(t, err, "QueryTxs")
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
