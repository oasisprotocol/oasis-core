// Package tests is a collection of transactinon pool test cases.
package tests

import (
	"crypto"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
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

	t.Run("TestAddBatch", func(t *testing.T) {
		testAddBatch(t, pool)
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
}

func testBasic(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize:       51,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 100,
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.Add([]byte("hello world"))
	require.NoError(t, err, "Add")

	err = pool.Add([]byte("hello world"))
	require.Error(t, err, "Add error on duplicates")

	err = pool.Add(make([]byte, 200))
	require.Error(t, err, "Add error on oversized calls")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = pool.Add([]byte(fmt.Sprintf("call %d", i)))
		require.NoError(t, err, "Add")
	}

	err = pool.Add([]byte("another call"))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, pool.Size(), "Size")

	batch := pool.GetBatch(false)
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 51, pool.Size(), "Size")

	err = pool.RemoveBatch(batch)
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 41, pool.Size(), "Size")

	if pool.IsQueue() {
		require.EqualValues(t, batch[0], []byte("hello world"))
		for i := 0; i < 9; i++ {
			require.EqualValues(t, batch[i+1], []byte(fmt.Sprintf("call %d", i)))
		}
		// Not a duplicate anymore.
		err = pool.Add([]byte("hello world"))
		require.NoError(t, err, "Add")
		require.EqualValues(t, 42, pool.Size(), "Size")

		pool.Clear()
		require.EqualValues(t, 0, pool.Size(), "Size")
	}
}

func testGetBatch(t *testing.T, pool api.TxPool) {
	pool.Clear()
	err := pool.UpdateConfig(api.Config{
		MaxPoolSize:       51,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 100,
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.Add([]byte("hello world"))
	require.NoError(t, err, "Add")

	batch := pool.GetBatch(false)
	require.Empty(t, batch, "GetBatch empty if no batch available")

	batch = pool.GetBatch(true)
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, pool.Size(), "Size")

	err = pool.RemoveBatch(batch)
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 0, pool.Size(), "Size")
}

func testAddBatch(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize:       51,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 100,
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.AddBatch([][]byte{
		[]byte("hello world"),
		[]byte("hello world"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	})
	// AddBatch should notify error about duplicate transaction.
	require.Error(t, err, "AddBatch")
	// Inserting transactions should still succeed.
	require.EqualValues(t, 4, pool.Size(), "Size")

	for i := 0; i < 10; i++ {
		_ = pool.AddBatch([][]byte{
			[]byte(fmt.Sprintf("a %d", i)),
			[]byte(fmt.Sprintf("b %d", i)),
			[]byte(fmt.Sprintf("c %d", i)),
			[]byte(fmt.Sprintf("d %d", i)),
			[]byte(fmt.Sprintf("e %d", i)),
		})
	}
	require.True(t, pool.Size() <= 51, "queue must not overflow")
}

func testRemoveBatch(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize:       51,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 100,
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.RemoveBatch([][]byte{})
	require.NoError(t, err, "RemoveBatch empty queue")

	err = pool.AddBatch([][]byte{
		[]byte("hello world"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	})
	require.NoError(t, err, "AddBatch")
	require.EqualValues(t, 4, pool.Size(), "Size")

	err = pool.RemoveBatch([][]byte{})
	require.NoError(t, err, "RemoveBatch empty batch")
	require.EqualValues(t, 4, pool.Size(), "Size")

	err = pool.RemoveBatch([][]byte{
		[]byte("hello world"),
		[]byte("two"),
	})
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 2, pool.Size(), "Size")

	err = pool.RemoveBatch([][]byte{
		[]byte("hello world"),
	})
	require.NoError(t, err, "RemoveBatch not existing batch")
	require.EqualValues(t, 2, pool.Size(), "Size")
}

func testUpdateConfig(t *testing.T, pool api.TxPool) {
	pool.Clear()

	err := pool.UpdateConfig(api.Config{
		MaxPoolSize:       50,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 100,
	})
	require.NoError(t, err, "UpdateConfig")

	err = pool.Add([]byte("hello world 1"))
	require.NoError(t, err, "Add")
	err = pool.Add([]byte("hello world 2"))
	require.NoError(t, err, "Add")

	batch := pool.GetBatch(false)
	require.Empty(t, batch, "no transactions should be returned")

	// Update configuration to BatchSize=1.
	err = pool.UpdateConfig(api.Config{
		MaxPoolSize:       50,
		MaxBatchSize:      1,
		MaxBatchSizeBytes: 100,
	})
	require.NoError(t, err, "UpdateConfig")

	batch = pool.GetBatch(false)
	require.Len(t, batch, 1, "one transaction should be returned")

	require.NoError(t, pool.RemoveBatch(batch), "remove batch")
	require.EqualValues(t, 1, pool.Size(), "one transaction should remain")

	// Update configuration back to BatchSize=10.
	err = pool.UpdateConfig(api.Config{
		MaxPoolSize:       50,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 100,
	})
	require.NoError(t, err, "UpdateConfig")
	// Make sure the transaction is still there.
	require.EqualValues(t, 1, pool.Size(), "transaction should remain after update")

	// Update configuration to MaxBatchSizeBytes=1.
	err = pool.UpdateConfig(api.Config{
		MaxPoolSize:       50,
		MaxBatchSize:      10,
		MaxBatchSizeBytes: 1,
	})
	require.NoError(t, err, "UpdateConfig")
	// Make sure the transaction was removed.
	require.EqualValues(t, 0, pool.Size(), "transaction should get removed on update")
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

	batchSize := 100

	b.Run(fmt.Sprintf("AddBatch:%d", batchSize), func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			// Exclude preparation.
			b.StopTimer()
			pool.Clear()
			_ = pool.UpdateConfig(api.Config{
				MaxPoolSize:       10000000,
				MaxBatchSize:      10000000,
				MaxBatchSizeBytes: 10000000,
			})
			for _, tx := range values {
				_ = pool.Add(tx)
			}
			b.StartTimer()

			cntr := 0
			for {
				startIdx := cntr * batchSize
				endIdx := (cntr + 1) * batchSize
				if endIdx > len(values) {
					break
				}
				cntr++
				_ = pool.AddBatch(values[(startIdx):(endIdx)])
			}
		}
	})

	b.Run(fmt.Sprintf("GetBatch:%d", batchSize), func(b *testing.B) {
		// Exclude preparation.
		b.StopTimer()
		pool.Clear()
		_ = pool.UpdateConfig(api.Config{
			MaxPoolSize:       10000000,
			MaxBatchSize:      10000000,
			MaxBatchSizeBytes: 10000000,
		})
		for _, tx := range values {
			_ = pool.Add(tx)
		}
		b.StartTimer()

		for i := 0; i < 1000; i++ {
			pool.GetBatch(true)
		}
	})

	b.Run(fmt.Sprintf("RemoveBatch:%d", batchSize), func(b *testing.B) {
		pool.Clear()
		_ = pool.UpdateConfig(api.Config{
			MaxPoolSize:       10000000,
			MaxBatchSize:      10000000,
			MaxBatchSizeBytes: 10000000,
		})
		for _, tx := range values {
			_ = pool.Add(tx)
		}
		b.StartTimer()

		cntr := 0
		for {
			startIdx := cntr * batchSize
			endIdx := (cntr + 1) * batchSize
			if endIdx > len(values) {
				break
			}
			cntr++
			_ = pool.RemoveBatch(values[(startIdx):(endIdx)])
		}
	})
}

func prepareValues(b *testing.B) [][]byte {
	b.StopTimer()
	rngSrc, err := drbg.New(crypto.SHA512, []byte("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeed"), nil, []byte("incoming queue benchmark"))
	if err != nil {
		panic(err)
	}
	rng := rand.New(mathrand.New(rngSrc))

	values := [][]byte{}
	for i := 0; i < 1000000; i++ {
		b := make([]byte, rng.Intn(128/2)+1)
		rng.Read(b)
		values = append(values, b)
	}
	b.StartTimer()

	return values
}
