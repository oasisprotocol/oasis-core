package txpool

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

func newPendingTx(tx []byte) *pendingTx {
	return &pendingTx{
		Tx:     tx,
		TxHash: hash.NewFromBytes(tx),
	}
}

func TestCheckTxQueueBasic(t *testing.T) {
	queue := newCheckTxQueue(51, 10)

	err := queue.Add(newPendingTx([]byte("hello world")))
	require.NoError(t, err, "Add")

	err = queue.Add(newPendingTx([]byte("hello world")))
	require.Error(t, err, "Add error on duplicates")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.Add(newPendingTx([]byte(fmt.Sprintf("call %d", i))))
		require.NoError(t, err, "Add")
	}

	err = queue.Add(newPendingTx([]byte("another call")))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, queue.Size(), "Size")

	batch := queue.GetBatch()
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 51, queue.Size(), "Size")

	queue.RemoveBatch(batch)
	require.EqualValues(t, 41, queue.Size(), "Size")

	require.EqualValues(t, batch[0].Tx, []byte("hello world"))
	for i := 0; i < 9; i++ {
		require.EqualValues(t, batch[i+1].Tx, []byte(fmt.Sprintf("call %d", i)))
	}
	// Not a duplicate anymore.
	err = queue.Add(newPendingTx([]byte("hello world")))
	require.NoError(t, err, "Add")
	require.EqualValues(t, 42, queue.Size(), "Size")

	queue.Clear()
	require.EqualValues(t, 0, queue.Size(), "Size")
}

func TestCheckTxQueueGetBatch(t *testing.T) {
	queue := newCheckTxQueue(51, 10)

	batch := queue.GetBatch()
	require.EqualValues(t, 0, len(batch), "Batch size")
	require.EqualValues(t, 0, queue.Size(), "Size")

	err := queue.Add(newPendingTx([]byte("hello world")))
	require.NoError(t, err, "Add")

	batch = queue.GetBatch()
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, queue.Size(), "Size")

	queue.RemoveBatch(batch)
	require.EqualValues(t, 0, queue.Size(), "Size")
}

func TestCheckTxQueueRemoveBatch(t *testing.T) {
	queue := newCheckTxQueue(51, 10)

	queue.RemoveBatch([]*pendingTx{})

	for _, tx := range [][]byte{
		[]byte("hello world"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	} {
		require.NoError(t, queue.Add(newPendingTx(tx)), "Add")
	}
	require.EqualValues(t, 4, queue.Size(), "Size")

	queue.RemoveBatch([]*pendingTx{})
	require.EqualValues(t, 4, queue.Size(), "Size")

	queue.RemoveBatch([]*pendingTx{
		newPendingTx([]byte("hello world")),
		newPendingTx([]byte("two")),
	})
	require.EqualValues(t, 2, queue.Size(), "Size")

	queue.RemoveBatch([]*pendingTx{
		newPendingTx([]byte("hello world")),
	})
	require.EqualValues(t, 2, queue.Size(), "Size")
}
