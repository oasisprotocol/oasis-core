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

func testBasic(t *testing.T, queue *priorityQueue) {
	queue.Clear()

	queue.UpdateMaxPoolSize(51)
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	tx := transaction.RawCheckedTransaction([]byte("hello world"))

	err := queue.Add(tx)
	require.NoError(t, err, "Add")

	err = queue.Add(tx)
	require.Error(t, err, "Add error on duplicates")

	oversized := transaction.RawCheckedTransaction(make([]byte, 200))
	err = queue.Add(oversized)
	require.Error(t, err, "Add error on oversized calls")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.Add(
			transaction.RawCheckedTransaction([]byte(fmt.Sprintf("call %d", i))),
		)
		require.NoError(t, err, "Add")
	}

	err = queue.Add(transaction.RawCheckedTransaction([]byte("another call")))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, queue.Size(), "Size")

	batch := queue.GetBatch(false)
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 51, queue.Size(), "Size")

	hashes := make([]hash.Hash, 0, len(batch))
	for _, tx := range batch {
		hashes = append(hashes, tx.Hash())
		hashes = append(hashes, tx.Hash()) // Duplicate to ensure this is handled correctly.
	}
	queue.RemoveTxBatch(hashes)
	require.EqualValues(t, 41, queue.Size(), "Size")
}

func testGetBatch(t *testing.T, queue *priorityQueue) {
	queue.Clear()

	queue.UpdateMaxPoolSize(51)
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	err := queue.Add(transaction.RawCheckedTransaction([]byte("hello world")))
	require.NoError(t, err, "Add")

	batch := queue.GetBatch(false)
	require.Empty(t, batch, "GetBatch empty if no batch available")

	batch = queue.GetBatch(true)
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, queue.Size(), "Size")

	batch = queue.GetPrioritizedBatch(nil, 10)
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, queue.Size(), "Size")

	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	queue.RemoveTxBatch(hashes)
	require.EqualValues(t, 0, queue.Size(), "Size")
}

func testRemoveTxBatch(t *testing.T, queue *priorityQueue) {
	queue.Clear()

	queue.UpdateMaxPoolSize(51)
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	queue.RemoveTxBatch([]hash.Hash{})

	// TODO: change to add.
	for _, tx := range []*transaction.CheckedTransaction{
		transaction.RawCheckedTransaction([]byte("hello world")),
		transaction.RawCheckedTransaction([]byte("one")),
		transaction.RawCheckedTransaction([]byte("two")),
		transaction.RawCheckedTransaction([]byte("three")),
	} {
		require.NoError(t, queue.Add(tx), "Add")
	}
	require.EqualValues(t, 4, queue.Size(), "Size")

	queue.RemoveTxBatch([]hash.Hash{})
	require.EqualValues(t, 4, queue.Size(), "Size")

	queue.RemoveTxBatch([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
		hash.NewFromBytes([]byte("two")),
	})
	require.EqualValues(t, 2, queue.Size(), "Size")

	queue.RemoveTxBatch([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
	})
	require.EqualValues(t, 2, queue.Size(), "Size")
}

func testUpdateConfig(t *testing.T, queue *priorityQueue) {
	queue.Clear()

	queue.UpdateMaxPoolSize(50)
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})

	err := queue.Add(transaction.RawCheckedTransaction([]byte("hello world 1")))
	require.NoError(t, err, "Add")
	err = queue.Add(transaction.RawCheckedTransaction([]byte("hello world 2")))
	require.NoError(t, err, "Add")

	batch := queue.GetBatch(false)
	require.Empty(t, batch, "no transactions should be returned")

	// Update configuration to BatchSize=1.
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     1,
		transaction.WeightSizeBytes: 100,
	})

	batch = queue.GetBatch(false)
	require.Len(t, batch, 1, "one transaction should be returned")

	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	queue.RemoveTxBatch(hashes)
	require.EqualValues(t, 1, queue.Size(), "one transaction should remain")

	// Update configuration back to BatchSize=10.
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 100,
	})
	// Make sure the transaction is still there.
	require.EqualValues(t, 1, queue.Size(), "transaction should remain after update")

	// Update configuration to MaxBatchSizeBytes=1.
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     10,
		transaction.WeightSizeBytes: 1,
	})

	batch = queue.GetBatch(true)
	require.Empty(t, batch, "no transaction should be returned")
	// Make sure the transaction was removed.
	require.EqualValues(t, 0, queue.Size(), "transaction should get removed after update")
}

func testWeights(t *testing.T, queue *priorityQueue) {
	queue.Clear()

	queue.UpdateMaxPoolSize(51)
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:             10,
		transaction.WeightSizeBytes:         100,
		transaction.WeightConsensusMessages: 10,
		"custom_weight":                     5,
	})

	err := queue.Add(transaction.NewCheckedTransaction(
		[]byte("hello world 1"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 9,
			"custom_weight":                     1,
		},
	))
	require.NoError(t, err, "Add")

	err = queue.Add(transaction.NewCheckedTransaction(
		[]byte("hello world 2"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 1,
			"custom_weight":                     4,
		},
	))
	require.NoError(t, err, "Add")

	err = queue.Add(transaction.NewCheckedTransaction(
		[]byte("hello world 3"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 1,
			"custom_weight":                     1,
		},
	))
	require.NoError(t, err, "Add")

	batch := queue.GetBatch(true)
	require.Len(t, batch, 2, "two transactions should be returned")

	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:             10,
		transaction.WeightSizeBytes:         100,
		transaction.WeightConsensusMessages: 11,
		"custom_weight":                     6,
	})

	batch = queue.GetBatch(true)
	require.Len(t, batch, 3, "two transactions should be returned")

	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:             10,
		transaction.WeightSizeBytes:         100,
		transaction.WeightConsensusMessages: 5,
		"custom_weight":                     5,
	})

	batch = queue.GetBatch(true)
	require.Len(t, batch, 2, "two transactions should be returned")
}

func testPriority(t *testing.T, queue *priorityQueue) {
	queue.Clear()

	queue.UpdateMaxPoolSize(3)
	queue.UpdateWeightLimits(map[transaction.Weight]uint64{
		transaction.WeightCount:     3,
		transaction.WeightSizeBytes: 100,
	})

	txs := []*transaction.CheckedTransaction{
		transaction.NewCheckedTransaction(
			[]byte("hello world 10"),
			10,
			nil,
		),
		transaction.NewCheckedTransaction(
			[]byte("hello world 5"),
			5,
			nil,
		),
		transaction.NewCheckedTransaction(
			[]byte("hello world 20"),
			20,
			nil,
		),
	}
	for _, tx := range txs {
		require.NoError(t, queue.Add(tx), "Add")
	}

	batch := queue.GetBatch(true)
	require.Len(t, batch, 3, "three transactions should be returned")
	require.EqualValues(
		t,
		[]*transaction.CheckedTransaction{
			txs[2], // 20
			txs[0], // 10
			txs[1], // 5
		},
		batch,
		"elements should be returned by priority",
	)

	batch = queue.GetPrioritizedBatch(nil, 2)
	require.Len(t, batch, 2, "two transactions should be returned")
	require.EqualValues(
		t,
		[]*transaction.CheckedTransaction{
			txs[2], // 20
			txs[0], // 10
		},
		batch,
		"elements should be returned by priority",
	)

	offsetTx := txs[2].Hash()
	batch = queue.GetPrioritizedBatch(&offsetTx, 2)
	require.Len(t, batch, 2, "two transactions should be returned")
	require.EqualValues(
		t,
		[]*transaction.CheckedTransaction{
			txs[0], // 10
			txs[1], // 5
		},
		batch,
		"elements should be returned by priority",
	)

	offsetTx.Empty()
	batch = queue.GetPrioritizedBatch(&offsetTx, 2)
	require.Len(t, batch, 0, "no transactions should be returned on invalid hash")

	// When the pool is full, a higher priority transaction should still get queued.
	highTx := transaction.NewCheckedTransaction(
		[]byte("hello world 6"),
		6,
		nil,
	)
	err := queue.Add(highTx)
	require.NoError(t, err, "higher priority transaction should still get queued")

	batch = queue.GetBatch(true)
	require.Len(t, batch, 3, "three transactions should be returned")
	require.EqualValues(
		t,
		[]*transaction.CheckedTransaction{
			txs[2], // 20
			txs[0], // 10
			highTx, // 6
		},
		batch,
		"elements should be returned by priority",
	)

	// A lower priority transaction should not get queued.
	lowTx := transaction.NewCheckedTransaction(
		[]byte("hello world 3"),
		3,
		nil,
	)
	err = queue.Add(lowTx)
	require.Error(t, err, "lower priority transaction should not get queued")
}

func BenchmarkPriorityQueue(b *testing.B) {
	queue := newPriorityQueue(10, nil)
	values := prepareValues(b)
	batchSize := 10000

	b.Run(fmt.Sprintf("Add:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		queue.Clear()
		queue.UpdateMaxPoolSize(10000000)
		queue.UpdateWeightLimits(map[transaction.Weight]uint64{
			transaction.WeightCount:     10000000,
			transaction.WeightSizeBytes: 10000000,
		})

		for i := 0; i < b.N; i++ {
			for _, tx := range values {
				_ = queue.Add(tx)
			}
		}
	})

	b.Run(fmt.Sprintf("GetBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		queue.Clear()
		queue.UpdateMaxPoolSize(10000000)
		queue.UpdateWeightLimits(map[transaction.Weight]uint64{
			transaction.WeightCount:     10000000,
			transaction.WeightSizeBytes: 10000000,
		})

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for _, tx := range values {
				_ = queue.Add(tx)
			}
			b.StartTimer()
			_ = queue.GetBatch(true)
		}
	})

	b.Run(fmt.Sprintf("RemoveTxBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		queue.Clear()
		queue.UpdateMaxPoolSize(10000000)
		queue.UpdateWeightLimits(map[transaction.Weight]uint64{
			transaction.WeightCount:     10000000,
			transaction.WeightSizeBytes: 10000000,
		})

		hashes := make([]hash.Hash, len(values))
		for i, tx := range values {
			_ = queue.Add(tx)
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
			queue.RemoveTxBatch(hashes[(startIdx):(endIdx)])
		}
	})
}

func prepareValues(b *testing.B) []*transaction.CheckedTransaction {
	b.StopTimer()
	rngSrc, err := drbg.New(crypto.SHA512, []byte("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeed"), nil, []byte("incoming queue benchmark"))
	if err != nil {
		panic(err)
	}
	rng := rand.New(mathrand.New(rngSrc))

	values := []*transaction.CheckedTransaction{}
	for i := 0; i < 1000000; i++ {
		b := make([]byte, rng.Intn(128/2)+1)
		rng.Read(b)
		values = append(values, transaction.RawCheckedTransaction(b))
	}
	b.StartTimer()

	return values
}
