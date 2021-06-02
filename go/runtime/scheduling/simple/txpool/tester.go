// Package tests is a collection of transactinon pool test cases.
package tests

import (
	"crypto"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// TxPoolImplementationTests runs the tx pool implementation tests.
func TxPoolImplementationTests(
	t *testing.T,
	pool api.TxPool,
) {
	// Run the test cases.
	t.Run("TestBasic", func(t *testing.T) {
		testBasic(t, pool)
	})

	t.Run("TestGetBatch", func(t *testing.T) {
		testGetBatch(t, pool)
	})

	t.Run("TestRemoveBatch", func(t *testing.T) {
		testRemoveBatch(t, pool)
	})

	t.Run("TestUpdateConfig", func(t *testing.T) {
		testUpdateConfig(t, pool)
	})

	t.Run("TestWeights", func(t *testing.T) {
		testWeights(t, pool)
	})

	t.Run("TestPriority", func(t *testing.T) {
		testPriority(t, pool)
	})
}

func testBasic(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize: 51,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 100,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	tx := transaction.RawCheckedTransaction([]byte("hello world"))

	err = pool.Add(tx)
	require.NoError(t, err, "Add")

	err = pool.Add(tx)
	require.Error(t, err, "Add error on duplicates")

	oversized := transaction.RawCheckedTransaction(make([]byte, 200))
	err = pool.Add(oversized)
	require.Error(t, err, "Add error on oversized calls")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = pool.Add(
			transaction.RawCheckedTransaction([]byte(fmt.Sprintf("call %d", i))),
		)
		require.NoError(t, err, "Add")
	}

	err = pool.Add(transaction.RawCheckedTransaction([]byte("another call")))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, pool.Size(), "Size")

	batch := pool.GetBatch(false)
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 51, pool.Size(), "Size")

	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	err = pool.RemoveBatch(hashes)
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 41, pool.Size(), "Size")
}

func testGetBatch(t *testing.T, pool api.TxPool) {
	pool.Clear()
	err := pool.UpdateConfig(api.Config{
		MaxPoolSize: 51,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 100,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.Add(transaction.RawCheckedTransaction([]byte("hello world")))
	require.NoError(t, err, "Add")

	batch := pool.GetBatch(false)
	require.Empty(t, batch, "GetBatch empty if no batch available")

	batch = pool.GetBatch(true)
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, pool.Size(), "Size")

	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	err = pool.RemoveBatch(hashes)
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 0, pool.Size(), "Size")
}

func testRemoveBatch(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize: 51,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 100,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.RemoveBatch([]hash.Hash{})
	require.NoError(t, err, "RemoveBatch empty queue")

	// TODO: change to add.
	for _, tx := range []*transaction.CheckedTransaction{
		transaction.RawCheckedTransaction([]byte("hello world")),
		transaction.RawCheckedTransaction([]byte("one")),
		transaction.RawCheckedTransaction([]byte("two")),
		transaction.RawCheckedTransaction([]byte("three")),
	} {
		require.NoError(t, pool.Add(tx), "Add")
	}
	require.EqualValues(t, 4, pool.Size(), "Size")

	err = pool.RemoveBatch([]hash.Hash{})
	require.NoError(t, err, "RemoveBatch empty batch")
	require.EqualValues(t, 4, pool.Size(), "Size")

	err = pool.RemoveBatch([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
		hash.NewFromBytes([]byte("two")),
	})
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 2, pool.Size(), "Size")

	err = pool.RemoveBatch([]hash.Hash{
		hash.NewFromBytes([]byte("hello world")),
	})
	require.NoError(t, err, "RemoveBatch not existing batch")
	require.EqualValues(t, 2, pool.Size(), "Size")
}

func testUpdateConfig(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 100,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.Add(transaction.RawCheckedTransaction([]byte("hello world 1")))
	require.NoError(t, err, "Add")
	err = pool.Add(transaction.RawCheckedTransaction([]byte("hello world 2")))
	require.NoError(t, err, "Add")

	batch := pool.GetBatch(false)
	require.Empty(t, batch, "no transactions should be returned")

	// Update configuration to BatchSize=1.
	err = pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     1,
			transaction.WeightSizeBytes: 100,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	batch = pool.GetBatch(false)
	require.Len(t, batch, 1, "one transaction should be returned")

	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	require.NoError(t, pool.RemoveBatch(hashes), "remove batch")
	require.EqualValues(t, 1, pool.Size(), "one transaction should remain")

	// Update configuration back to BatchSize=10.
	err = pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 100,
		},
	})
	require.NoError(t, err, "UpdateConfig")
	// Make sure the transaction is still there.
	require.EqualValues(t, 1, pool.Size(), "transaction should remain after update")

	// Update configuration to MaxBatchSizeBytes=1.
	err = pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 1,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	batch = pool.GetBatch(true)
	require.Empty(t, batch, "no transaction should be returned")
	// Make sure the transaction was removed.
	require.EqualValues(t, 0, pool.Size(), "transaction should get removed after update")
}

func testWeights(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:             10,
			transaction.WeightSizeBytes:         100,
			transaction.WeightConsensusMessages: 10,
			"custom_weight":                     5,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.Add(transaction.NewCheckedTransaction(
		[]byte("hello world 1"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 9,
			"custom_weight":                     1,
		},
	))
	require.NoError(t, err, "Add")

	err = pool.Add(transaction.NewCheckedTransaction(
		[]byte("hello world 2"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 1,
			"custom_weight":                     4,
		},
	))
	require.NoError(t, err, "Add")

	err = pool.Add(transaction.NewCheckedTransaction(
		[]byte("hello world 3"),
		0,
		map[transaction.Weight]uint64{
			transaction.WeightConsensusMessages: 1,
			"custom_weight":                     1,
		},
	))
	require.NoError(t, err, "Add")

	batch := pool.GetBatch(true)
	require.Len(t, batch, 2, "two transactions should be returned")

	err = pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:             10,
			transaction.WeightSizeBytes:         100,
			transaction.WeightConsensusMessages: 11,
			"custom_weight":                     6,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	batch = pool.GetBatch(true)
	require.Len(t, batch, 3, "two transactions should be returned")

	err = pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:             10,
			transaction.WeightSizeBytes:         100,
			transaction.WeightConsensusMessages: 5,
			"custom_weight":                     5,
		},
	})
	require.NoError(t, err, "UpdateConfig")

	batch = pool.GetBatch(true)
	require.Len(t, batch, 2, "two transactions should be returned")
}

func testPriority(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize: 50,
		WeightLimits: map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 100,
		},
	})
	require.NoError(t, err, "UpdateConfig")

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
		require.NoError(t, pool.Add(tx), "Add")
	}

	batch := pool.GetBatch(true)
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
}

// TxPoolImplementationBenchmarks runs the tx pool implementation benchmarks.
func TxPoolImplementationBenchmarks(
	b *testing.B,
	pool api.TxPool,
) {
	b.Run("BenchmarkTxPool", func(b *testing.B) {
		benchmarkIncommingQueue(b, pool)
	})
}

func benchmarkIncommingQueue(b *testing.B, pool api.TxPool) {
	values := prepareValues(b)

	batchSize := 10000

	b.Run(fmt.Sprintf("Add:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		pool.Clear()
		_ = pool.UpdateConfig(api.Config{
			MaxPoolSize: 10000000,
			WeightLimits: map[transaction.Weight]uint64{
				transaction.WeightCount:     10000000,
				transaction.WeightSizeBytes: 10000000,
			},
		})

		for i := 0; i < b.N; i++ {
			for _, tx := range values {
				_ = pool.Add(tx)
			}
		}
	})

	b.Run(fmt.Sprintf("GetBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		pool.Clear()
		_ = pool.UpdateConfig(api.Config{
			MaxPoolSize: 10000000,
			WeightLimits: map[transaction.Weight]uint64{
				transaction.WeightCount:     10000000,
				transaction.WeightSizeBytes: 10000000,
			},
		})

		for i := 0; i < b.N; i++ {
			b.StopTimer()
			for _, tx := range values {
				_ = pool.Add(tx)
			}
			b.StartTimer()
			_ = pool.GetBatch(true)
		}
	})

	b.Run(fmt.Sprintf("RemoveBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		pool.Clear()
		_ = pool.UpdateConfig(api.Config{
			MaxPoolSize: 10000000,
			WeightLimits: map[transaction.Weight]uint64{
				transaction.WeightCount:     10000000,
				transaction.WeightSizeBytes: 10000000,
			},
		})

		hashes := make([]hash.Hash, len(values))
		for i, tx := range values {
			_ = pool.Add(tx)
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
			_ = pool.RemoveBatch(hashes[(startIdx):(endIdx)])
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
