package txpool

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

func newPendingTx(tx []byte) *PendingCheckTransaction {
	return &PendingCheckTransaction{
		TxQueueMeta: &TxQueueMeta{
			raw:  tx,
			hash: hash.NewFromBytes(tx),
		},
	}
}

func TestCheckTxQueueBasic(t *testing.T) {
	queue := newCheckTxQueue(51, 10)

	err := queue.add(newPendingTx([]byte("hello world")))
	require.NoError(t, err, "Add")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.add(newPendingTx([]byte(fmt.Sprintf("call %d", i))))
		require.NoError(t, err, "Add")
	}

	err = queue.add(newPendingTx([]byte("another call")))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, queue.size(), "Size")

	batch := queue.pop()
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 41, queue.size(), "Size")

	require.EqualValues(t, batch[0].Raw(), []byte("hello world"))
	for i := 0; i < 9; i++ {
		require.EqualValues(t, batch[i+1].Raw(), []byte(fmt.Sprintf("call %d", i)))
	}

	queue.clear()
	require.EqualValues(t, 0, queue.size(), "Size")
}

func TestCheckTxQueuePop(t *testing.T) {
	queue := newCheckTxQueue(51, 10)

	batch := queue.pop()
	require.EqualValues(t, 0, len(batch), "Batch size")
	require.EqualValues(t, 0, queue.size(), "Size")

	err := queue.add(newPendingTx([]byte("hello world")))
	require.NoError(t, err, "Add")

	batch = queue.pop()
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 0, queue.size(), "Size")
}
