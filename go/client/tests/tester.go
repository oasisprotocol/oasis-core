// Package tests is a collection of client interface test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/client"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/worker/compute/committee"
)

const timeout = 1 * time.Second

// ClientImplementationTests runs the client interface implementation tests.
func ClientImplementationTests(
	t *testing.T,
	client *client.Client,
	runtimeID signature.PublicKey,
	rtNode *committee.Node,
) {
	t.Run("SubmitTx", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		testSubmitTransaction(ctx, t, runtimeID, client, rtNode)
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
	client *client.Client,
	rtNode *committee.Node,
) {
	// Submit a test transaction.
	testInput := []byte("hello world")
	testOutput, err := client.SubmitTx(ctx, testInput, runtimeID)

	// Check if everything is in order.
	require.NoError(t, err, "SubmitTx")
	require.EqualValues(t, testInput, testOutput)

	// We need to wait for the indexer to index the tags. We could have a channel
	// to subscribe to these updates and this would not be needed.
	time.Sleep(1 * time.Second)

	// Fetch blocks.
	blk, err := client.GetBlock(ctx, runtimeID, 1)
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 1, blk.Header.Round)

	blk, err = client.GetBlock(ctx, runtimeID, 2)
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 2, blk.Header.Round)

	blk, err = client.GetBlock(ctx, runtimeID, 0xffffffffffffffff)
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 2, blk.Header.Round)

	// Out of bounds block round.
	_, err = client.GetBlock(ctx, runtimeID, 3)
	require.Error(t, err, "GetBlock")

	// Fetch transaction.
	blk, input, output, err := client.GetTxn(ctx, runtimeID, 2, 0)
	require.NoError(t, err, "GetTxn(0)")
	require.EqualValues(t, 2, blk.Header.Round)
	require.EqualValues(t, testInput, input)
	require.EqualValues(t, testOutput, output)

	// Out of bounds transaction index.
	_, _, _, err = client.GetTxn(ctx, runtimeID, 2, 1)
	require.Error(t, err, "GetTxn(1)")

	// Get transaction by block hash and index.
	blk, input, output, err = client.GetTxnByBlockHash(ctx, runtimeID, blk.Header.EncodedHash(), 0)
	require.NoError(t, err, "GetTxnByBlockHash")
	require.EqualValues(t, 2, blk.Header.Round)
	require.EqualValues(t, testInput, input)
	require.EqualValues(t, testOutput, output)

	// Invalid block hash.
	var invalidHash hash.Hash
	invalidHash.Empty()
	_, _, _, err = client.GetTxnByBlockHash(ctx, runtimeID, invalidHash, 0)
	require.Error(t, err, "GetTxnByBlockHash(invalid)")

	// Check that indexer has indexed block keys (check the mock worker for key/values).
	blk, err = client.QueryBlock(ctx, runtimeID, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 2, blk.Header.Round)

	// Check that indexer has indexed txn keys (check the mock worker for key/values).
	blk, index, input, output, err := client.QueryTxn(ctx, runtimeID, []byte("txn_foo"), []byte("txn_bar"))
	require.NoError(t, err, "QueryTxn")
	require.EqualValues(t, 2, blk.Header.Round)
	require.EqualValues(t, 0, index)
	require.EqualValues(t, testInput, input)
	require.EqualValues(t, testOutput, output)

	// Transactions (check the mock worker for content).
	txns, err := client.GetTransactions(ctx, runtimeID, blk.Header.InputHash)
	require.NoError(t, err, "GetTransactions(input)")
	require.Len(t, txns, 1)
	require.EqualValues(t, testInput, txns[0])

	txns, err = client.GetTransactions(ctx, runtimeID, blk.Header.OutputHash)
	require.NoError(t, err, "GetTransactions(output)")
	require.Len(t, txns, 1)
	require.EqualValues(t, testOutput, txns[0])
}
