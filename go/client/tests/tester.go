// Package tests is a collection of client interface test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/client"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/worker/committee"
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

	// Check that indexer has indexed keys (check the mock worker for key/values).
	blk, err := client.QueryBlock(ctx, runtimeID, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "QueryBlock")
	require.EqualValues(t, 2, blk.Header.Round)
}
