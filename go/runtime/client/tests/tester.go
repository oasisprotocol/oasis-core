// Package tests is a collection of client interface test cases.
package tests

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/mock"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// Keep this above the test network's max batch timeout.
const timeout = 2 * time.Second

// ClientImplementationTests runs the client interface implementation tests.
func ClientImplementationTests(
	t *testing.T,
	client api.RuntimeClient,
	runtimeID common.Namespace,
) {
	// Include a timestamp so each test invocation uses an unique input.
	testInput := "octopus at:" + time.Now().String()
	t.Run("SubmitTx", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		testSubmitTransaction(ctx, t, runtimeID, client, testInput)
	})

	t.Run("Query", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		testQuery(ctx, t, runtimeID, client, testInput)
	})

	noWaitInput := "squid at: " + time.Now().String()
	t.Run("SubmitTxNoWait", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		testSubmitTransactionNoWait(ctx, t, runtimeID, client, noWaitInput)
	})

	t.Run("FailSubmitTx", func(t *testing.T) {
		ctx, cancelFunc := context.WithTimeout(context.Background(), timeout)
		defer cancelFunc()
		testFailSubmitTransaction(ctx, t, runtimeID, client, testInput)
	})
}

func testSubmitTransaction(
	ctx context.Context,
	t *testing.T,
	runtimeID common.Namespace,
	c api.RuntimeClient,
	input string,
) {
	testInput := []byte(input)
	// Submit a test transaction.
	resp, err := c.SubmitTxMeta(ctx, &api.SubmitTxRequest{Data: testInput, RuntimeID: runtimeID})

	// Check if everything is in order.
	require.NoError(t, err, "SubmitTxMeta")
	require.Nil(t, resp.CheckTxError, "SubmitTxMeta check tx error")
	require.EqualValues(t, testInput, resp.Output)
	require.True(t, resp.Round > 0, "SubmitTxMeta round should be non zero")
}

func testFailSubmitTransaction(
	ctx context.Context,
	t *testing.T,
	runtimeID common.Namespace,
	c api.RuntimeClient,
	input string,
) {
	// Failures during CheckTx.
	resp, err := c.SubmitTxMeta(ctx, &api.SubmitTxRequest{Data: mock.CheckTxFailInput, RuntimeID: runtimeID})
	require.NoError(t, err, "SubmitTxMeta")
	require.EqualValues(t, &protocol.Error{
		Module: "mock",
		Code:   1,
	}, resp.CheckTxError, "SubmitTxMeta should fail check tx")

	_, err = c.SubmitTx(ctx, &api.SubmitTxRequest{Data: mock.CheckTxFailInput, RuntimeID: runtimeID})
	require.Error(t, err, "SubmitTx should fail check tx")

	err = c.SubmitTxNoWait(ctx, &api.SubmitTxRequest{Data: mock.CheckTxFailInput, RuntimeID: runtimeID})
	require.Error(t, err, "SubmitTxNoWait should fail check tx")

	// Failures for unsupported runtimes.
	var unsupportedRuntimeID common.Namespace
	err = unsupportedRuntimeID.UnmarshalHex("0000000000000000BADF00BADF00BADF00BADF00BADF00BADF00BADF00BADF00")
	require.NoError(t, err, "UnmarshalHex")

	_, err = c.SubmitTx(ctx, &api.SubmitTxRequest{Data: []byte("irrelevant"), RuntimeID: unsupportedRuntimeID})
	require.Error(t, err, "SubmitTx should fail for unsupported runtime")
}

func testQuery(
	ctx context.Context,
	t *testing.T,
	runtimeID common.Namespace,
	c api.RuntimeClient,
	input string,
) {
	// Fetch genesis block.
	genBlk, err := c.GetGenesisBlock(ctx, runtimeID)
	require.NoError(t, err, "GetGenesisBlock")
	require.EqualValues(t, 0, genBlk.Header.Round, "GetGenesisBlock should have Round: 0")

	// Based on SubmitTx and the mock worker.
	testInput := []byte(input)

	// Fetch blocks.
	blk, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: 1})
	// Epoch transition from TestNode/ExecutorWorker/InitialEpochTransition
	require.NoError(t, err, "GetBlock")
	require.EqualValues(t, 1, blk.Header.Round)

	// Normal block from TestNode/ExecutorWorker/QueueTx
	blk, err = c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: 0xffffffffffffffff})

	// Normal block from TestNode/Client/SubmitTx
	// There can be multiple of these if ClientImplementationTests is run multiple times.
	require.NoError(t, err, "GetBlock")
	require.True(t, blk.Header.Round >= 3)
	expectedLatestRound := blk.Header.Round

	blkLatest, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: api.RoundLatest})
	require.NoError(t, err, "GetBlock(RoundLatest)")
	require.EqualValues(t, expectedLatestRound, blkLatest.Header.Round)

	// Out of bounds block round.
	_, err = c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: expectedLatestRound + 1})
	require.Error(t, err, "GetBlock")

	// Last retained block.
	blkLr, err := c.GetLastRetainedBlock(ctx, runtimeID)
	require.NoError(t, err, "GetLastRetainedBlock")
	require.EqualValues(t, genBlk.Header.Round, blkLr.Header.Round)

	// Transactions (check the mock worker for content).
	txns, err := c.GetTransactions(ctx, &api.GetTransactionsRequest{RuntimeID: runtimeID, Round: blk.Header.Round})
	require.NoError(t, err, "GetTransactions")
	require.Len(t, txns, 1)
	// Check for values from TestNode/Client/SubmitTx
	require.EqualValues(t, testInput, txns[0])

	// Transactions with results (check the mock worker for content).
	txnsWithResults, err := c.GetTransactionsWithResults(ctx, &api.GetTransactionsRequest{RuntimeID: runtimeID, Round: blk.Header.Round})
	require.NoError(t, err, "GetTransactionsWithResults")
	require.Len(t, txnsWithResults, 1)
	// Check for values from TestNode/Client/SubmitTx
	require.EqualValues(t, testInput, txnsWithResults[0].Tx)
	require.EqualValues(t, testInput, txnsWithResults[0].Result)
	require.Len(t, txnsWithResults[0].Events, 1)
	require.EqualValues(t, []byte("txn_foo"), txnsWithResults[0].Events[0].Key)
	require.EqualValues(t, []byte("txn_bar"), txnsWithResults[0].Events[0].Value)

	// Check events query (see mock worker for emitted events).
	events, err := c.GetEvents(ctx, &api.GetEventsRequest{RuntimeID: runtimeID, Round: 3})
	require.NoError(t, err, "GetEvents")
	require.Len(t, events, 1)
	require.EqualValues(t, []byte("txn_foo"), events[0].Key)
	require.EqualValues(t, []byte("txn_bar"), events[0].Value)

	// Query genesis block again.
	genBlk2, err := c.GetGenesisBlock(ctx, runtimeID)
	require.NoError(t, err, "GetGenesisBlock2")
	require.EqualValues(t, genBlk, genBlk2, "GetGenesisBlock should match previous GetGenesisBlock")

	// Query runtime.
	// Since we are using the mock runtime host the response should be a CBOR-serialized method name
	// with the added " world" string.
	rsp, err := c.Query(ctx, &api.QueryRequest{
		RuntimeID: runtimeID,
		Round:     blk.Header.Round,
		Method:    "hello",
	})
	require.NoError(t, err, "Query")
	var decResp string
	err = cbor.Unmarshal(rsp.Data, &decResp)
	require.NoError(t, err, "cbor.Unmarshal(<QueryResponse.Data>)")
	require.True(t, strings.HasPrefix(decResp, "hello world"), "Query response should be correct")

	rsp, err = c.Query(ctx, &api.QueryRequest{
		RuntimeID: runtimeID,
		Round:     1,
		Method:    "hello",
	})
	require.NoError(t, err, "Query")
	var decResp2 string
	err = cbor.Unmarshal(rsp.Data, &decResp2)
	require.NoError(t, err, "cbor.Unmarshal(<QueryResponse.Data>)")
	require.True(t, strings.HasPrefix(decResp2, "hello world"), "Query response at round 1 should be correct")
	require.NotEqualValues(t, decResp, decResp2, "Query responses for different rounds should not be equal (round consensus height should be included in response)")

	rsp, err = c.Query(ctx, &api.QueryRequest{
		RuntimeID: runtimeID,
		Round:     1,
		Method:    "hello",
	})
	require.NoError(t, err, "Query")
	var decResp3 string
	err = cbor.Unmarshal(rsp.Data, &decResp3)
	require.NoError(t, err, "cbor.Unmarshal(<QueryResponse.Data>)")
	require.True(t, strings.HasPrefix(decResp3, "hello world"), "Query response at round 1 should be correct")
	require.EqualValues(t, decResp2, decResp3, "Query responses for same round should be equal (round consensus height should be included in response)")

	// Make sure that using api.RoundLatest works for queries.
	rsp, err = c.Query(ctx, &api.QueryRequest{
		RuntimeID: runtimeID,
		Round:     api.RoundLatest,
		Method:    "hello",
	})
	require.NoError(t, err, "Query")
	var decResp4 string
	err = cbor.Unmarshal(rsp.Data, &decResp4)
	require.NoError(t, err, "cbor.Unmarshal(<QueryResponse.Data>)")
	require.True(t, strings.HasPrefix(decResp4, "hello world"), "Query response at latest round should be correct")

	// Execute CheckTx using the mock runtime host.
	err = c.CheckTx(ctx, &api.CheckTxRequest{
		RuntimeID: runtimeID,
		Data:      []byte("test checktx request"),
	})
	require.NoError(t, err, "CheckTx")
}

func testSubmitTransactionNoWait(
	ctx context.Context,
	t *testing.T,
	runtimeID common.Namespace,
	c api.RuntimeClient,
	input string,
) {
	// Based on SubmitTx and the mock worker.
	testInput := []byte(input)

	// Query current block.
	_, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: runtimeID, Round: api.RoundLatest})
	require.NoError(t, err, "GetBlock(RoundLatest)")

	// Submit a test transaction.
	err = c.SubmitTxNoWait(ctx, &api.SubmitTxRequest{Data: testInput, RuntimeID: runtimeID})

	// Check if everything is in order.
	require.NoError(t, err, "SubmitTxNoWait")
}
