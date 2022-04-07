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
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

func TestPriorityQueue(t *testing.T) {
	queue := newPriorityQueue(10, nil)

	t.Run("TestBasic", func(t *testing.T) {
		testBasic(t, queue)
	})

	t.Run("TestGetBatch", func(t *testing.T) {
		testGetBatch(t, queue)
	})

	t.Run("TestRemoveTxBatch", func(t *testing.T) {
		testRemoveTxBatch(t, queue)
	})

	t.Run("TestUpdateConfig", func(t *testing.T) {
		testUpdateConfig(t, queue)
	})

	t.Run("TestWeights", func(t *testing.T) {
		testWeights(t, queue)
	})

	t.Run("TestPriority", func(t *testing.T) {
		testPriority(t, queue)
	})
}

func newTestTransaction(data []byte, priority uint64, weights map[transaction.Weight]uint64) *Transaction {
	tx := newTransaction(data, txStatusPendingCheck)
	tx.setChecked(&protocol.CheckTxMetadata{
		Priority: priority,
		Weights:  weights,
	})
	return tx
}

func testBasic(t *testing.T, queue *priorityQueue) {
	queue.clear()

	queue.updateMaxPoolSize(51)
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	tx := newTestTransaction([]byte("hello world"), 0, nil)

	err := queue.add(tx)
	require.NoError(t, err, "Add")

	err = queue.add(tx)
	require.Error(t, err, "Add error on duplicates")

	oversized := newTestTransaction(make([]byte, 200), 0, nil)
	err = queue.add(oversized)
	require.Error(t, err, "Add error on oversized calls")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.add(
			newTestTransaction([]byte(fmt.Sprintf("call %d", i)), 0, nil),
		)
		require.NoError(t, err, "Add")
	}

	err = queue.add(newTestTransaction([]byte("another call"), 0, nil))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, queue.size(), "Size")

	batch := queue.getBatch(false)
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

func testGetBatch(t *testing.T, queue *priorityQueue) {
	queue.clear()

	queue.updateMaxPoolSize(51)
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	err := queue.add(newTestTransaction([]byte("hello world"), 0, nil))
	require.NoError(t, err, "Add")

	batch := queue.getBatch(false)
	require.Empty(t, batch, "GetBatch empty if no batch available")

	batch = queue.getBatch(true)
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, queue.size(), "Size")

	batch = queue.getPrioritizedBatch(nil, 10)
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, queue.size(), "Size")

	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	queue.removeTxBatch(hashes)
	require.EqualValues(t, 0, queue.size(), "Size")
}

func testRemoveTxBatch(t *testing.T, queue *priorityQueue) {
	queue.clear()

	queue.updateMaxPoolSize(51)
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	queue.removeTxBatch([]hash.Hash{})

	for _, tx := range []*Transaction{
		newTestTransaction([]byte("hello world"), 0, nil),
		newTestTransaction([]byte("one"), 0, nil),
		newTestTransaction([]byte("two"), 0, nil),
		newTestTransaction([]byte("three"), 0, nil),
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

func testUpdateConfig(t *testing.T, queue *priorityQueue) {
	queue.clear()

	queue.updateMaxPoolSize(50)
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	err := queue.add(newTestTransaction([]byte("hello world 1"), 0, nil))
	require.NoError(t, err, "Add")
	err = queue.add(newTestTransaction([]byte("hello world 2"), 0, nil))
	require.NoError(t, err, "Add")

	batch := queue.getBatch(false)
	require.Empty(t, batch, "no transactions should be returned")

	// Update configuration to BatchSize=1.
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     1,
		transaction.WeightSizeBytes: 100,
	})

	batch = queue.getBatch(false)
	require.Len(t, batch, 1, "one transaction should be returned")

	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	queue.removeTxBatch(hashes)
	require.EqualValues(t, 1, queue.size(), "one transaction should remain")

	// Update configuration back to BatchSize=10.
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})
	// Make sure the transaction is still there.
	require.EqualValues(t, 1, queue.size(), "transaction should remain after update")

	// Update configuration to MaxBatchSizeBytes=1.
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 1,
	})

	batch = queue.getBatch(true)
	require.Empty(t, batch, "no transaction should be returned")
	// Make sure the transaction was removed.
	require.EqualValues(t, 0, queue.size(), "transaction should get removed after update")
}

func testWeights(t *testing.T, queue *priorityQueue) {
	queue.clear()

	queue.updateMaxPoolSize(51)
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:             10,
		transaction.WeightSizeBytes:         100,
		transaction.WeightConsensusMessages: 10,
		"custom_weight":                     5,
	})

	err := queue.add(newTestTransaction(
		[]byte("hello world 1"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 9,
			"custom_weight":                     1,
		},
	))
	require.NoError(t, err, "Add")

	err = queue.add(newTestTransaction(
		[]byte("hello world 2"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 1,
			"custom_weight":                     4,
		},
	))
	require.NoError(t, err, "Add")

	err = queue.add(newTestTransaction(
		[]byte("hello world 3"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 1,
			"custom_weight":                     1,
		},
	))
	require.NoError(t, err, "Add")

	batch := queue.getBatch(true)
	require.Len(t, batch, 2, "two transactions should be returned")

	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:             10,
		transaction.WeightSizeBytes:         100,
		transaction.WeightConsensusMessages: 11,
		"custom_weight":                     6,
	})

	batch = queue.getBatch(true)
	require.Len(t, batch, 3, "two transactions should be returned")

	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:             10,
		transaction.WeightSizeBytes:         100,
		transaction.WeightConsensusMessages: 5,
		"custom_weight":                     5,
	})

	batch = queue.getBatch(true)
	require.Len(t, batch, 2, "two transactions should be returned")
}

func testPriority(t *testing.T, queue *priorityQueue) {
	queue.clear()

	queue.updateMaxPoolSize(3)
	queue.updateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     3,
		transaction.WeightSizeBytes: 100,
	})

	txs := []*Transaction{
		newTestTransaction(
			[]byte("hello world 10"),
			10,
			nil,
		),
		newTestTransaction(
			[]byte("hello world 5"),
			5,
			nil,
		),
		newTestTransaction(
			[]byte("hello world 20"),
			20,
			nil,
		),
	}
	for _, tx := range txs {
		require.NoError(t, queue.add(tx), "Add")
	}

	batch := queue.getBatch(true)
	require.Len(t, batch, 3, "three transactions should be returned")
	require.EqualValues(
		t,
		[]*Transaction{
			txs[2], // 20
			txs[0], // 10
			txs[1], // 5
		},
		batch,
		"elements should be returned by priority",
	)

	batch = queue.getPrioritizedBatch(nil, 2)
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
		nil,
	)
	err := queue.add(highTx)
	require.NoError(t, err, "higher priority transaction should still get queued")

	batch = queue.getBatch(true)
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
		nil,
	)
	err = queue.add(lowTx)
	require.Error(t, err, "lower priority transaction should not get queued")
}

func BenchmarkPriorityQueue(b *testing.B) {
	queue := newPriorityQueue(10, nil)
	values := prepareValues(b)
	batchSize := 10000

	b.Run(fmt.Sprintf("Add:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		queue.clear()
		queue.updateMaxPoolSize(10000000)
		queue.updateWeightLimits(map[transaction.Weight]uint64{
			transaction.WeightCount:     10000000,
			transaction.WeightSizeBytes: 10000000,
		})

		for i := 0; i < b.N; i++ {
			for _, tx := range values {
				_ = queue.add(tx)
			}
		}
	})

	b.Run(fmt.Sprintf("GetBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		queue.clear()
		queue.updateMaxPoolSize(10000000)
		queue.updateWeightLimits(map[transaction.Weight]uint64{
			transaction.WeightCount:     10000000,
			transaction.WeightSizeBytes: 10000000,
		})

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for _, tx := range values {
				_ = queue.add(tx)
			}
			b.StartTimer()
			_ = queue.getBatch(true)
		}
	})

	b.Run(fmt.Sprintf("RemoveTxBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		queue.clear()
		queue.updateMaxPoolSize(10000000)
		queue.updateWeightLimits(map[transaction.Weight]uint64{
			transaction.WeightCount:     10000000,
			transaction.WeightSizeBytes: 10000000,
		})

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
		values = append(values, newTestTransaction(b, 0, nil))
	}
	b.StartTimer()

	return values
}
