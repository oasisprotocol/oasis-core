package txpool

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

func newTestTransaction(data []byte, priority uint64) *MainQueueTransaction {
	tx := newTransaction(TxQueueMeta{
		raw:       data,
		hash:      hash.NewFromBytes(data),
		firstSeen: time.Now(),
	})
	tx.setChecked(&protocol.CheckTxMetadata{
		Priority: priority,
	})
	return tx
}

func TestScheduleQueueBasic(t *testing.T) {
	require := require.New(t)

	queue := newScheduleQueue(51)

	tx := newTestTransaction([]byte("hello world"), 0)

	err := queue.add(tx)
	require.NoError(err, "Add")

	err = queue.add(tx)
	require.Error(err, "Add error on duplicates")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.add(
			newTestTransaction([]byte(fmt.Sprintf("call %d", i)), 0),
		)
		require.NoError(err, "Add")
	}

	err = queue.add(newTestTransaction([]byte("another call"), 0))
	require.Error(err, "Add error on queue full")

	require.EqualValues(51, queue.size(), "Size")

	batch := queue.getPrioritizedBatch(nil, 10)
	require.EqualValues(10, len(batch), "Batch size")
	require.EqualValues(51, queue.size(), "Size")

	hashes := make([]hash.Hash, 0, len(batch))
	for _, tx := range batch {
		hashes = append(hashes, tx.Hash())
		hashes = append(hashes, tx.Hash()) // Duplicate to ensure this is handled correctly.
	}
	queue.remove(hashes)
	require.EqualValues(41, queue.size(), "Size")

	queue.clear()
	require.EqualValues(0, queue.size(), "Size")
}

func TestScheduleQueueRemoveTxBatch(t *testing.T) {
	require := require.New(t)

	queue := newScheduleQueue(51)
	queue.remove([]hash.Hash{})

	for _, tx := range []*MainQueueTransaction{
		newTestTransaction([]byte("hello world"), 0),
		newTestTransaction([]byte("one"), 0),
		newTestTransaction([]byte("two"), 0),
		newTestTransaction([]byte("three"), 0),
	} {
		require.NoError(queue.add(tx), "Add")
	}
	require.EqualValues(4, queue.size(), "Size")

	queue.remove([]hash.Hash{})
	require.EqualValues(4, queue.size(), "Size")

	queue.remove([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
		hash.NewFromBytes([]byte("two")),
	})
	require.EqualValues(2, queue.size(), "Size")

	queue.remove([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
	})
	require.EqualValues(2, queue.size(), "Size")
}

func TestScheduleQueuePriority(t *testing.T) {
	require := require.New(t)

	queue := newScheduleQueue(3)

	txs := []*MainQueueTransaction{
		newTestTransaction(
			[]byte("hello world 10"),
			10,
		),
		newTestTransaction(
			[]byte("hello world 5"),
			5,
		),
		newTestTransaction(
			[]byte("hello world 20"),
			20,
		),
	}
	for _, tx := range txs {
		require.NoError(queue.add(tx), "Add")
	}

	batch := queue.getPrioritizedBatch(nil, 2)
	require.Len(batch, 2, "two transactions should be returned")
	require.EqualValues(
		[]*MainQueueTransaction{
			txs[2], // 20
			txs[0], // 10
		},
		batch,
		"elements should be returned by priority",
	)

	offsetTx := txs[2].Hash()
	batch = queue.getPrioritizedBatch(&offsetTx, 2)
	require.Len(batch, 2, "two transactions should be returned")
	require.EqualValues(
		[]*MainQueueTransaction{
			txs[0], // 10
			txs[1], // 5
		},
		batch,
		"elements should be returned by priority",
	)

	offsetTx.Empty()
	batch = queue.getPrioritizedBatch(&offsetTx, 2)
	require.Len(batch, 0, "no transactions should be returned on invalid hash")

	// When the pool is full, a higher priority transaction should still get queued.
	highTx := newTestTransaction(
		[]byte("hello world 6"),
		6,
	)
	err := queue.add(highTx)
	require.NoError(err, "higher priority transaction should still get queued")

	batch = queue.getPrioritizedBatch(nil, 3)
	require.Len(batch, 3, "three transactions should be returned")
	require.EqualValues(
		[]*MainQueueTransaction{
			txs[2], // 20
			txs[0], // 10
			highTx, // 6
		},
		batch,
		"elements should be returned by priority",
	)

	// A lower priority transaction should not get queued.
	lowTx := newTestTransaction(
		[]byte("hello world 3"),
		3,
	)
	err = queue.add(lowTx)
	require.Error(err, "lower priority transaction should not get queued")
	require.Equal(ErrQueueFull, err)
}

func TestScheduleQueueSender(t *testing.T) {
	require := require.New(t)

	const (
		sender1 = "sender1"
		sender2 = "sender2"
	)

	queue := newScheduleQueue(10)

	tx := newTestTransaction([]byte("hello world s1 p0"), 0)
	tx.sender = sender1

	err := queue.add(tx)
	require.NoError(err, "Add")

	tx = newTestTransaction([]byte("hello world s2 p0"), 0)
	tx.sender = sender2

	tx = newTestTransaction([]byte("hello worldd s1 p0"), 0)
	tx.sender = sender1

	err = queue.add(tx)
	require.Error(err, "Add")
	require.Equal(ErrReplacementTxPriorityTooLow, err)
	require.Equal(1, queue.size())

	tx = newTestTransaction([]byte("hello world 2"), 10)
	tx.sender = sender1

	err = queue.add(tx)
	require.NoError(err, "Add")
	require.Equal(1, queue.size())

	queue.remove([]hash.Hash{tx.Hash()})
	require.Equal(0, queue.size())
}
