package txpool

import (
	"fmt"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

var testTransactionID int64

func newTestTransaction(priority int, sender int, seq int, stateSeq int) *MainQueueTransaction {
	id := atomic.AddInt64(&testTransactionID, 1)
	raw := []byte(fmt.Sprintf("transaction-%d", id))
	tx := newTransaction(TxQueueMeta{
		raw:       raw,
		hash:      hash.NewFromBytes(raw),
		firstSeen: time.Now(),
	})
	tx.setChecked(&protocol.CheckTxMetadata{
		Priority:       uint64(priority),
		Sender:         []byte(fmt.Sprintf("sender-%d", sender)),
		SenderSeq:      uint64(seq),
		SenderStateSeq: uint64(stateSeq),
	})
	return tx
}

func TestTransactionBlockEmpty(t *testing.T) {
	raws := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
	}

	blk := newTransactionBlock()
	require.True(t, blk.empty())

	blk = newTransactionBlock(raws...)
	require.False(t, blk.empty())
}

func TestTransactionBlockSize(t *testing.T) {
	raws := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
	}

	blk := newTransactionBlock()
	require.Equal(t, 0, blk.size())

	blk = newTransactionBlock(raws...)
	require.Equal(t, 3, blk.size())
}

func TestTransactionBlockFirst(t *testing.T) {
	raws := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
	}

	blk := newTransactionBlock()
	_, ok := blk.first()
	require.False(t, ok)

	blk = newTransactionBlock(raws...)
	tx, ok := blk.first()
	require.True(t, ok)
	require.Equal(t, raws[0], tx.raw)
	require.Equal(t, blk, tx.block)
	require.Equal(t, 0, tx.position)
}

func TestTransactionBlockLast(t *testing.T) {
	raws := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
	}

	blk := newTransactionBlock()
	_, ok := blk.last()
	require.False(t, ok)

	blk = newTransactionBlock(raws...)
	tx, ok := blk.last()
	require.True(t, ok)
	require.Equal(t, raws[2], tx.raw)
	require.Equal(t, blk, tx.block)
	require.Equal(t, 2, tx.position)
	require.NotEqual(t, raws[1], tx.raw)
}

func TestTransactionBlockPop(t *testing.T) {
	raws := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
	}

	blk := newTransactionBlock(raws...)

	for i := range len(raws) {
		n := len(raws) - 1 - i
		tx, ok := blk.pop()
		require.True(t, ok)
		require.Equal(t, raws[n], tx.raw)
		require.Equal(t, blk, tx.block)
		require.Equal(t, n, tx.position)
		require.Equal(t, n, blk.size())
	}

	_, ok := blk.pop()
	require.False(t, ok)
}

func TestTransactionBlockSplit(t *testing.T) {
	raws := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
	}

	blk := newTransactionBlock()
	for _, i := range []int{0, 10} {
		left, right := blk.split(i)
		require.Equal(t, 0, left.size())
		require.Equal(t, 0, right.size())
	}

	for i := range len(raws) + 1 {
		blk = newTransactionBlock(raws...)

		left, right := blk.split(i)
		require.Equal(t, i, left.size())
		require.Equal(t, 3-i, right.size())
		require.True(t, blk.empty())

		for j, tx := range left.txs {
			require.Equal(t, raws[j], tx.raw)
			require.Equal(t, left, tx.block)
			require.Equal(t, j, tx.position)
		}

		for j, tx := range right.txs {
			require.Equal(t, raws[i+j], tx.raw)
			require.Equal(t, right, tx.block)
			require.Equal(t, j, tx.position)
		}
	}
}

func TestTransactionBlockMerge(t *testing.T) {
	raws := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 0, 0),
	}

	for i := range len(raws) + 1 {
		left := newTransactionBlock(raws[:i]...)
		require.Equal(t, i, left.size())

		right := newTransactionBlock(raws[i:]...)
		require.Equal(t, 3-i, right.size())

		left.merge(right)
		require.Equal(t, 3, left.size())
		require.True(t, right.empty())

		for j, tx := range left.txs {
			require.Equal(t, raws[j], tx.raw)
			require.Equal(t, left, tx.block)
			require.Equal(t, j, tx.position)
		}
	}
}

func TestTransactionBlockPartition(t *testing.T) {
	t.Run("Ascending", func(t *testing.T) {
		raws := []*MainQueueTransaction{
			newTestTransaction(0, 0, 1, 0),
			newTestTransaction(1, 0, 2, 0),
			newTestTransaction(2, 0, 3, 0),
		}

		blk := newTransactionBlock(raws...)
		blks := blk.partition()
		require.Len(t, blks, 1)
		require.Len(t, blks[0].txs, 3)
	})

	t.Run("Descending", func(t *testing.T) {
		raws := []*MainQueueTransaction{
			newTestTransaction(2, 0, 1, 0),
			newTestTransaction(1, 0, 2, 0),
			newTestTransaction(0, 0, 3, 0),
		}

		blk := newTransactionBlock(raws...)
		blks := blk.partition()
		require.Len(t, blks, 3)
		require.Len(t, blks[0].txs, 1)
		require.Len(t, blks[1].txs, 1)
		require.Len(t, blks[2].txs, 1)
	})

	t.Run("Mixed", func(t *testing.T) {
		raws := []*MainQueueTransaction{
			newTestTransaction(4, 0, 1, 0),
			newTestTransaction(5, 0, 2, 0),
			newTestTransaction(1, 0, 3, 0),
			newTestTransaction(3, 0, 4, 0),
			newTestTransaction(2, 0, 5, 0),
			newTestTransaction(0, 0, 6, 0),
		}

		blk := newTransactionBlock(raws...)
		blks := blk.partition()
		require.Len(t, blks, 3)
		require.Len(t, blks[0].txs, 2)
		require.Len(t, blks[1].txs, 3)
		require.Len(t, blks[2].txs, 1)
	})
}

func TestScheduleQueueSize(t *testing.T) {
	txs := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 1, 0),
		newTestTransaction(0, 0, 2, 0),
	}

	t.Run("Empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		require.Equal(t, 0, q.size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}
		require.Equal(t, len(txs), q.size())
	})
}

func TestScheduleQueueClear(t *testing.T) {
	txs := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 1, 0),
		newTestTransaction(0, 0, 2, 0),
	}

	t.Run("Empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		q.clear()
		require.Equal(t, 0, q.size())
	})

	t.Run("Non-empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}
		require.Equal(t, len(txs), q.size())

		q.clear()
		require.Equal(t, 0, q.size())
	})
}

func TestScheduleQueueGet(t *testing.T) {
	txs := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 1, 0),
		newTestTransaction(0, 0, 2, 0),
	}

	t.Run("Empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)

		_, ok := q.get(txs[0].hash)
		require.False(t, ok)
	})

	t.Run("Exists", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}
		tx, ok := q.get(txs[0].hash)
		require.True(t, ok)
		require.Equal(t, txs[0], tx)
	})

	t.Run("Missing", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		for _, tx := range txs[1:] {
			err := q.add(tx)
			require.NoError(t, err)
		}
		_, ok := q.get(txs[0].hash)
		require.False(t, ok)
	})
}

func TestScheduleQueueAll(t *testing.T) {
	txs := []*MainQueueTransaction{
		newTestTransaction(0, 0, 0, 0),
		newTestTransaction(0, 0, 1, 0),
		newTestTransaction(0, 0, 2, 0),
	}

	t.Run("Empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		actual := q.all()
		require.Empty(t, actual)
	})

	t.Run("Non-empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}
		actual := q.all()
		require.ElementsMatch(t, txs, actual)
	})
}

func TestScheduleQueueAdd(t *testing.T) {
	t.Run("Multiple transactions", func(t *testing.T) {
		q := newScheduleQueue(10, 10)

		testCases := []struct {
			sender int
			seq    int
		}{
			// First sender.
			{sender: 0, seq: 0},
			{sender: 0, seq: 1},
			{sender: 0, seq: 8},
			{sender: 0, seq: 5},
			{sender: 0, seq: 7},
			// Second sender.
			{sender: 1, seq: 2},
			{sender: 1, seq: 1},
			{sender: 1, seq: 0},
			// Third sender.
			{sender: 2, seq: 0},
		}

		for i, tc := range testCases {
			tx := newTestTransaction(0, tc.sender, tc.seq, 0)

			err := q.add(tx)
			require.NoError(t, err)
			require.Equal(t, i+1, q.size())

			tx, ok := q.get(tx.hash)
			require.True(t, ok)
			require.Equal(t, tx, tx)
		}
	})

	t.Run("Duplicate transaction", func(t *testing.T) {
		q := newScheduleQueue(10, 10)
		tx := newTestTransaction(0, 0, 0, 0)

		// Add transaction.
		err := q.add(tx)
		require.NoError(t, err)
		require.Equal(t, 1, q.size())

		tx, ok := q.get(tx.hash)
		require.True(t, ok)
		require.Equal(t, tx, tx)

		// Add transaction again.
		err = q.add(tx)
		require.Error(t, err)
		require.ErrorContains(t, err, "duplicate transaction")
		require.Equal(t, 1, q.size())
	})

	t.Run("Replace transaction", func(t *testing.T) {
		q := newScheduleQueue(10, 10)

		// Transactions with the same sequence number but different priorities.
		txs := []*MainQueueTransaction{
			newTestTransaction(1, 0, 0, 0),
			newTestTransaction(0, 0, 0, 0), // Lower priority.
			newTestTransaction(2, 0, 0, 0), // Higher priority.
		}

		// Add the first transaction.
		err := q.add(txs[0])
		require.NoError(t, err)
		require.Equal(t, 1, q.size())

		tx, ok := q.get(txs[0].hash)
		require.True(t, ok)
		require.Equal(t, txs[0], tx)

		// Add transaction with lower priority.
		err = q.add(txs[1])
		require.Error(t, err)
		require.ErrorContains(t, err, "replacement transaction has lower priority")
		require.Equal(t, 1, q.size())

		_, ok = q.get(txs[1].hash)
		require.False(t, ok)

		// Add transaction with higher priority.
		err = q.add(txs[2])
		require.NoError(t, err)
		require.Equal(t, 1, q.size())

		tx, ok = q.get(txs[2].hash)
		require.True(t, ok)
		require.Equal(t, txs[2], tx)

		// Verify final state.
		_, ok = q.get(txs[0].hash)
		require.False(t, ok)

		_, ok = q.get(txs[1].hash)
		require.False(t, ok)

		_, ok = q.get(txs[2].hash)
		require.True(t, ok)
	})

	t.Run("Full queue", func(t *testing.T) {
		q := newScheduleQueue(5, 10)

		// Fill the queue.
		txs := make([]*MainQueueTransaction, 0, 5)
		for i := range 5 {
			tx := newTestTransaction(1, 0, i, 0)
			txs = append(txs, tx)
		}
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}

		// Accept transaction with higher priority.
		tx := newTestTransaction(2, 0, 5, 0)
		err := q.add(tx)
		require.NoError(t, err)

		actual, ok := q.get(tx.hash)
		require.True(t, ok)
		require.Equal(t, tx, actual)

		_, ok = q.get(txs[4].hash)
		require.False(t, ok)

		// Reject transaction with lower priority.
		tx = newTestTransaction(0, 0, 6, 0)
		err = q.add(tx)
		require.Error(t, err)
		require.ErrorContains(t, err, "schedule queue is full")
	})

	t.Run("Full sender queue", func(t *testing.T) {
		q := newScheduleQueue(10, 5)

		// Fill the queue.
		txs := make([]*MainQueueTransaction, 0, 5)
		for i := range 5 {
			tx := newTestTransaction(0, 0, 1+i, 0)
			txs = append(txs, tx)
		}
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}

		// Accept transaction with lower sequence number.
		tx := newTestTransaction(0, 0, 0, 0)
		err := q.add(tx)
		require.NoError(t, err)

		actual, ok := q.get(tx.hash)
		require.True(t, ok)
		require.Equal(t, tx, actual)

		_, ok = q.get(txs[4].hash)
		require.False(t, ok)

		// Reject transaction with higher sequence number.
		tx = newTestTransaction(0, 0, 6, 0)
		err = q.add(tx)
		require.Error(t, err)
		require.ErrorContains(t, err, "sender queue is full")
	})

	t.Run("State sequence number", func(t *testing.T) {
		q := newScheduleQueue(10, 10)

		// Fill the queue.
		txs := make([]*MainQueueTransaction, 0, 5)
		for i := range 5 {
			tx := newTestTransaction(0, 0, i, 0)
			txs = append(txs, tx)
		}
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}
		require.Equal(t, 5, q.size())

		// Add transaction with high state sequence number.
		tx := newTestTransaction(0, 0, 5, 2)
		err := q.add(tx)
		require.NoError(t, err)

		// Verify that the first two transactions were removed.
		require.Equal(t, 4, q.size())

		txs = append(txs, tx)
		for _, tx := range txs[:2] {
			_, ok := q.get(tx.hash)
			require.False(t, ok)
		}
		for _, tx := range txs[2:] {
			actual, ok := q.get(tx.hash)
			require.True(t, ok)
			require.Equal(t, tx, actual)
		}
	})
}

func TestScheduleQueueRemove(t *testing.T) {
	t.Run("Empty", func(t *testing.T) {
		q := newScheduleQueue(10, 10)

		hashes := []hash.Hash{{1}}
		q.remove(hashes)
		require.Equal(t, 0, q.size())
	})

	t.Run("Existing", func(t *testing.T) {
		q := newScheduleQueue(10, 10)

		txs := []*MainQueueTransaction{
			newTestTransaction(0, 0, 0, 0),
			newTestTransaction(0, 0, 1, 0),
			newTestTransaction(0, 0, 2, 0),
		}
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}

		hashes := []hash.Hash{
			txs[0].hash,
			txs[2].hash,
			txs[2].hash, // Duplicate.
		}
		q.remove(hashes)
		require.Equal(t, 1, q.size())
	})

	t.Run("Non-existing", func(t *testing.T) {
		q := newScheduleQueue(10, 10)

		txs := []*MainQueueTransaction{
			newTestTransaction(0, 0, 0, 0),
			newTestTransaction(0, 0, 1, 0),
			newTestTransaction(0, 0, 2, 0),
		}
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}

		hashes := []hash.Hash{{1}, {2}, {3}}
		q.remove(hashes)
		require.Equal(t, 3, q.size())
	})
}

func TestScheduleQueuePrioritizedBatch(t *testing.T) {
	t.Run("Long block", func(t *testing.T) {
		q := newScheduleQueue(100, 10)

		// Add transactions.
		txs := make([]*MainQueueTransaction, 0, 10)
		for i := range 10 {
			tx := newTestTransaction(i, 0, i, 0)
			txs = append(txs, tx)
		}
		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}

		// Fetch all transactions.
		ordered := q.getPrioritizedBatchAll(nil, 100)
		require.Equal(t, txs, ordered)

		ordered = q.getPrioritizedBatch(nil, 100)
		require.Equal(t, txs, ordered)

		// Fetch first transactions.
		ordered = q.getPrioritizedBatchAll(nil, 5)
		require.Equal(t, txs[:5], ordered)

		ordered = q.getPrioritizedBatch(nil, 5)
		require.Equal(t, txs[:5], ordered)

		// Fetch middle transactions.
		ordered = q.getPrioritizedBatchAll(&txs[4].hash, 2)
		require.Equal(t, txs[5:7], ordered)

		ordered = q.getPrioritizedBatch(&txs[4].hash, 2)
		require.Equal(t, txs[5:7], ordered)

		// Fetch last transactions.
		ordered = q.getPrioritizedBatchAll(&txs[6].hash, 100)
		require.Equal(t, txs[7:], ordered)

		ordered = q.getPrioritizedBatch(&txs[6].hash, 100)
		require.Equal(t, txs[7:], ordered)
	})

	t.Run("Unit blocks", func(t *testing.T) {
		allPriorities := [][]int{
			{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			{9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
			{7, 2, 9, 0, 4, 6, 1, 8, 5, 3},
		}

		for _, priorities := range allPriorities {
			q := newScheduleQueue(10, 10)

			// Add transactions.
			txs := make([]*MainQueueTransaction, 0, 10)
			for i, priority := range priorities {
				tx := newTestTransaction(priority, i, 0, 0) // Different sender for every transaction.
				txs = append(txs, tx)

				err := q.add(tx)
				require.NoError(t, err)
			}

			// Sort transactions.
			sort.Slice(txs, func(i, j int) bool {
				return txs[i].priority > txs[j].priority
			})

			// Fetch all transactions.
			ordered := q.getPrioritizedBatchAll(nil, 100)
			require.Equal(t, txs, ordered)

			ordered = q.getPrioritizedBatch(nil, 100)
			require.ElementsMatch(t, txs, ordered)

			// Fetch a subset of transactions.
			ordered = q.getPrioritizedBatchAll(nil, 5)
			require.ElementsMatch(t, txs[:5], ordered)

			ordered = q.getPrioritizedBatch(nil, 5)
			require.ElementsMatch(t, txs[:5], ordered)

			// Fetch all transactions with offset.
			ordered = q.getPrioritizedBatchAll(&txs[2].hash, 100)
			require.Equal(t, txs[3:], ordered)

			ordered = q.getPrioritizedBatch(&txs[2].hash, 100)
			require.Equal(t, txs[3:], ordered)

			// Fetch a subset of transactions with offset.
			ordered = q.getPrioritizedBatchAll(&txs[2].hash, 5)
			require.Equal(t, txs[3:8], ordered)

			ordered = q.getPrioritizedBatch(&txs[2].hash, 5)
			require.Equal(t, txs[3:8], ordered)

			// Unknown offset.
			var hash hash.Hash

			ordered = q.getPrioritizedBatchAll(&hash, 5)
			require.Empty(t, ordered)

			ordered = q.getPrioritizedBatch(&hash, 5)
			require.Empty(t, ordered)
		}
	})

	t.Run("Blocks with gaps", func(t *testing.T) {
		q := newScheduleQueue(100, 10)

		// Add transactions.
		txs := []*MainQueueTransaction{
			newTestTransaction(2, 0, 1, 0), // B1, average priority 3.
			newTestTransaction(4, 0, 2, 0), // B1
			newTestTransaction(1, 0, 3, 0), // B2, average priority 1, gap 0.
			newTestTransaction(4, 0, 5, 0), // B3, average priority 4, gap 1.
			newTestTransaction(1, 0, 8, 0), // B4, average priority 2, gap 2.
			newTestTransaction(3, 0, 9, 0), // B4
		}

		for _, tx := range txs {
			err := q.add(tx)
			require.NoError(t, err)
		}

		// Fetch all transactions.
		ordered := q.getPrioritizedBatchAll(nil, 100)
		expected := []*MainQueueTransaction{
			txs[3],         // B3, priority 4.
			txs[0], txs[1], // B1, priority 3.
			txs[4], txs[5], // B4, priority 2.
			txs[2], // B2, priority 1.
		}
		require.Equal(t, expected, ordered)

		ordered = q.getPrioritizedBatch(nil, 100)
		expected = []*MainQueueTransaction{
			txs[0], txs[1], // B1, priority 3.
			txs[2], // B2, priority 1.
		}
		require.Equal(t, expected, ordered)

		// Fetch first transactions.
		ordered = q.getPrioritizedBatchAll(nil, 2)
		expected = []*MainQueueTransaction{
			txs[3], // B3, priority 4.
			txs[0], // B1, priority 3.
		}
		require.Equal(t, expected, ordered)

		ordered = q.getPrioritizedBatch(nil, 2)
		expected = []*MainQueueTransaction{
			txs[0], txs[1], // B1, priority 3.
		}
		require.Equal(t, expected, ordered)

		// Fetch middle transactions.
		ordered = q.getPrioritizedBatchAll(&txs[3].hash, 3)
		expected = []*MainQueueTransaction{
			txs[0], txs[1], // B1, priority 3.
			txs[4], // B4, priority 2.
		}
		require.Equal(t, expected, ordered)

		ordered = q.getPrioritizedBatch(&txs[0].hash, 1)
		expected = []*MainQueueTransaction{
			txs[1], // B1, priority 3.
		}
		require.Equal(t, expected, ordered)

		// Fetch last transactions.
		ordered = q.getPrioritizedBatchAll(&txs[4].hash, 100)
		expected = []*MainQueueTransaction{
			txs[5], // B4, priority 2.
			txs[2], // B2, priority 1.
		}
		require.Equal(t, expected, ordered)

		ordered = q.getPrioritizedBatch(&txs[0].hash, 100)
		expected = []*MainQueueTransaction{
			txs[1], // B1, priority 3.
			txs[2], // B2, priority 1.
		}
		require.Equal(t, expected, ordered)

		// Add missing transaction between B2 and B3.
		tx1 := newTestTransaction(0, 0, 4, 0) // Merges with B2 and B3.
		err := q.add(tx1)
		require.NoError(t, err)

		// Fetch all transactions.
		ordered = q.getPrioritizedBatchAll(nil, 100)
		expected = []*MainQueueTransaction{
			txs[0], txs[1], // B1, priority 3.
			txs[4], txs[5], // B4, priority 2.
			txs[2], tx1, txs[3], // B2 + tx1 + B3, priority 1.
		}
		require.Equal(t, expected, ordered)

		ordered = q.getPrioritizedBatch(nil, 100)
		expected = []*MainQueueTransaction{
			txs[0], txs[1], // B1, priority 3.
			txs[2], tx1, txs[3], // B2 + tx1 + B3, priority 1.
		}
		require.Equal(t, expected, ordered)

		// Add one missing transaction before B4.
		tx2 := newTestTransaction(0, 0, 7, 0) // Merges with B4.
		err = q.add(tx2)
		require.NoError(t, err)

		// Fetch all transactions.
		ordered = q.getPrioritizedBatchAll(nil, 100)
		expected = []*MainQueueTransaction{
			txs[0], txs[1], // B1, priority 3.
			txs[2], tx1, txs[3], // B2 + tx1 + B3, priority 1.
			tx2, txs[4], txs[5], // tx2 + B4, priority 1.
		}
		require.Equal(t, expected, ordered)

		ordered = q.getPrioritizedBatch(nil, 100)
		expected = []*MainQueueTransaction{
			txs[0], txs[1], // B1, priority 3.
			txs[2], tx1, txs[3], // B2 + tx1 + B3, priority 1.
		}
		require.Equal(t, expected, ordered)

		// Unknown offset.
		var hash hash.Hash

		ordered = q.getPrioritizedBatchAll(&hash, 5)
		require.Empty(t, ordered)

		ordered = q.getPrioritizedBatch(&hash, 5)
		require.Empty(t, ordered)
	})
}
