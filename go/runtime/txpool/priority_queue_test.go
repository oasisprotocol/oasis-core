package txpool

import (
	"crypto"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

func newTestTransaction(data []byte, priority uint64) *Transaction {
	tx := newTransaction(data, txStatusPendingCheck)
	tx.setChecked(&protocol.CheckTxMetadata{
		Priority: priority,
	})
	return tx
}

func TestPriorityQueueBasic(t *testing.T) {
	queue := newPriorityQueue(51)

	tx := newTestTransaction([]byte("hello world"), 0)

	err := queue.add(tx)
	require.NoError(t, err, "Add")

	err = queue.add(tx)
	require.Error(t, err, "Add error on duplicates")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.add(
			newTestTransaction([]byte(fmt.Sprintf("call %d", i)), 0),
		)
		require.NoError(t, err, "Add")
	}

	err = queue.add(newTestTransaction([]byte("another call"), 0))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, queue.size(), "Size")

	batch := queue.getPrioritizedBatch(nil, 10)
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 51, queue.size(), "Size")

	hashes := make([]hash.Hash, 0, len(batch))
	for _, tx := range batch {
		hashes = append(hashes, tx.Hash())
		hashes = append(hashes, tx.Hash()) // Duplicate to ensure this is handled correctly.
	}
	queue.removeTxBatch(hashes)
	require.EqualValues(t, 41, queue.size(), "Size")
}

func TestPriorityQueueRemoveTxBatch(t *testing.T) {
	queue := newPriorityQueue(51)
	queue.removeTxBatch([]hash.Hash{})

	for _, tx := range []*Transaction{
		newTestTransaction([]byte("hello world"), 0),
		newTestTransaction([]byte("one"), 0),
		newTestTransaction([]byte("two"), 0),
		newTestTransaction([]byte("three"), 0),
	} {
		require.NoError(t, queue.add(tx), "Add")
	}
	require.EqualValues(t, 4, queue.size(), "Size")

	queue.removeTxBatch([]hash.Hash{})
	require.EqualValues(t, 4, queue.size(), "Size")

	queue.removeTxBatch([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
		hash.NewFromBytes([]byte("two")),
	})
	require.EqualValues(t, 2, queue.size(), "Size")

	queue.removeTxBatch([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
	})
	require.EqualValues(t, 2, queue.size(), "Size")
}

func TestPriorityQueuePriority(t *testing.T) {
	queue := newPriorityQueue(3)

	txs := []*Transaction{
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
		require.NoError(t, queue.add(tx), "Add")
	}

	batch := queue.getPrioritizedBatch(nil, 2)
	require.Len(t, batch, 2, "two transactions should be returned")
	require.EqualValues(
		t,
		[]*Transaction{
			txs[2], // 20
			txs[0], // 10
		},
		batch,
		"elements should be returned by priority",
	)

	offsetTx := txs[2].Hash()
	batch = queue.getPrioritizedBatch(&offsetTx, 2)
	require.Len(t, batch, 2, "two transactions should be returned")
	require.EqualValues(
		t,
		[]*Transaction{
			txs[0], // 10
			txs[1], // 5
		},
		batch,
		"elements should be returned by priority",
	)

	offsetTx.Empty()
	batch = queue.getPrioritizedBatch(&offsetTx, 2)
	require.Len(t, batch, 0, "no transactions should be returned on invalid hash")

	// When the pool is full, a higher priority transaction should still get queued.
	highTx := newTestTransaction(
		[]byte("hello world 6"),
		6,
	)
	err := queue.add(highTx)
	require.NoError(t, err, "higher priority transaction should still get queued")

	batch = queue.getPrioritizedBatch(nil, 3)
	require.Len(t, batch, 3, "three transactions should be returned")
	require.EqualValues(
		t,
		[]*Transaction{
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
	require.Error(t, err, "lower priority transaction should not get queued")
}

func BenchmarkPriorityQueue(b *testing.B) {
	values := prepareValues(b)
	batchSize := 10000

	b.Run(fmt.Sprintf("Add:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		queue := newPriorityQueue(10000000)

		for i := 0; i < b.N; i++ {
			for _, tx := range values {
				_ = queue.add(tx)
			}
		}
	})

	b.Run(fmt.Sprintf("GetPrioritizedBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		queue := newPriorityQueue(10000000)

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for _, tx := range values {
				_ = queue.add(tx)
			}
			b.StartTimer()
			_ = queue.getPrioritizedBatch(nil, 10000000)
		}
	})

	b.Run(fmt.Sprintf("RemoveTxBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		queue := newPriorityQueue(10000000)

		hashes := make([]hash.Hash, len(values))
		for i, tx := range values {
			_ = queue.add(tx)
			hashes[i] = tx.Hash()
		}
		b.StartTimer()

		cntr := 0
		for i := 0; i < b.N; i++ {
			startIdx := cntr * batchSize
			endIdx := (cntr + 1) * batchSize
			if endIdx > len(values) {
				break
			}
			cntr++
			queue.removeTxBatch(hashes[(startIdx):(endIdx)])
		}
	})
}

func prepareValues(b *testing.B) []*Transaction {
	b.StopTimer()
	rngSrc, err := drbg.New(crypto.SHA512, []byte("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeed"), nil, []byte("incoming queue benchmark"))
	if err != nil {
		panic(err)
	}
	rng := rand.New(mathrand.New(rngSrc))

	var values []*Transaction
	for i := 0; i < 1000000; i++ {
		b := make([]byte, rng.Intn(128/2)+1)
		rng.Read(b)
		values = append(values, newTestTransaction(b, 0))
	}
	b.StartTimer()

	return values
}
