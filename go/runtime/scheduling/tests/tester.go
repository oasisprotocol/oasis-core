// Package tests is a collection of worker test cases.
package tests

import (
	"crypto"
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// SchedulerImplementationTests runs the scheduler implementation tests.
func SchedulerImplementationTests(t *testing.T, scheduler api.Scheduler) {
	// Run the test cases.
	t.Run("ScheduleTxs", func(t *testing.T) {
		testScheduleTransactions(t, scheduler)
	})
}

func testScheduleTransactions(t *testing.T, scheduler api.Scheduler) {
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions should be scheduled")

	// Test QueueTx.
	testTx := []byte("hello world")
	txBytes := hash.NewFromBytes(testTx)
	err := scheduler.QueueTx(testTx)
	require.NoError(t, err, "QueueTx(testTx)")
	require.True(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")

	// Test GetBatch.
	batch := scheduler.GetBatch(false)
	require.Empty(t, batch, "non-forced GetBatch should not return any transactions")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "transaction should remain in the queue")
	require.True(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")

	batch = scheduler.GetBatch(true)
	require.EqualValues(t, transaction.RawBatch{testTx}, batch, "transaction should be returned")
	require.True(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")

	// Test RemoveTxBatch.
	err = scheduler.RemoveTxBatch(batch)
	require.NoError(t, err, "RemoveTxBatch")
	require.False(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions should remain")

	// Test schedule batch.
	testBatch := [][]byte{
		[]byte("hello world"),
		[]byte("hello world2"),
		[]byte("hello world3"),
		[]byte("hello world4"),
	}
	err = scheduler.AppendTxBatch(testBatch)
	require.NoError(t, err, "AppendTxBatch(testBatch)")
	for _, tx := range testBatch {
		require.True(t, scheduler.IsQueued(hash.NewFromBytes(tx)), fmt.Sprintf("IsQueued(%s)", tx))
	}
	// Clear the queue.
	scheduler.Clear()
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions after flushing")

	// Test Update configuration.
	// First insert a transaction.
	err = scheduler.QueueTx(testTx)
	require.NoError(t, err, "QueueTx(testTx)")
	// Make sure transaction doesn't get scheduled.
	batch = scheduler.GetBatch(false)
	require.Empty(t, batch, "non-forced GetBatch should not return any transactions")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "transaction should remain in the queue")
	// Update configuration to BatchSize=1.
	err = scheduler.UpdateParameters(
		registry.TxnSchedulerParameters{
			Algorithm:         scheduler.Name(),
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 10000,
		},
	)
	require.NoError(t, err, "UpdateParameters")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "transaction should remain in the queue")
	// Make sure transaction gets scheduled now.
	batch = scheduler.GetBatch(false)
	require.Len(t, batch, 1, "transaction should be returned")

	// Test update clear transactions.
	// Update configuration back to BatchSize=10.
	err = scheduler.UpdateParameters(
		registry.TxnSchedulerParameters{
			Algorithm:         scheduler.Name(),
			MaxBatchSize:      10,
			MaxBatchSizeBytes: 10000,
		},
	)
	require.NoError(t, err, "UpdateParameters")
	// Insert a transaction.
	err = scheduler.QueueTx(testTx)
	require.NoError(t, err, "QueueTx(testTx)")
	// Make sure transaction is queued.
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "one transaction queued")
	// Update configuration to MaxBatchSizeBytes=1.
	err = scheduler.UpdateParameters(
		registry.TxnSchedulerParameters{
			Algorithm:         scheduler.Name(),
			MaxBatchSize:      10,
			MaxBatchSizeBytes: 1,
		},
	)
	require.NoError(t, err, "UpdateParameters")
	// Make sure the transaction was removed.
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "transaction should get removed on update")

	// Test invalid udpate.
	err = scheduler.UpdateParameters(
		registry.TxnSchedulerParameters{
			Algorithm: "invalid",
		},
	)
	require.Error(t, err, "UpdateParameters invalid udpate")
}

type benchmarkingDispatcher interface {
	Dispatch(batch transaction.RawBatch)
	DispatchedSize() int
}

type noOpDispatcher struct {
	DispatchedBatches transaction.RawBatch
	scheduler         api.Scheduler
}

func (t *noOpDispatcher) Dispatch(batch transaction.RawBatch) {
	if len(batch) == 0 {
		return
	}
	t.DispatchedBatches = append(t.DispatchedBatches, batch...)
	_ = t.scheduler.RemoveTxBatch(batch)
}

func (t *noOpDispatcher) DispatchedSize() int {
	return len(t.DispatchedBatches)
}

type delayDispatcher struct {
	rng               *rand.Rand
	delay             func(*rand.Rand) time.Duration
	DispatchedBatches transaction.RawBatch
	scheduler         api.Scheduler
}

func (t *delayDispatcher) Dispatch(batch transaction.RawBatch) {
	if len(batch) == 0 {
		return
	}
	<-time.After(t.delay(t.rng))
	t.DispatchedBatches = append(t.DispatchedBatches, batch...)
	_ = t.scheduler.RemoveTxBatch(batch)
}

func (t *delayDispatcher) DispatchedSize() int {
	return len(t.DispatchedBatches)
}

// SchedulerImplementationBenchmarks runs the scheduler implementation benchmarks.
func SchedulerImplementationBenchmarks(b *testing.B, scheduler api.Scheduler) {
	rngSrc, err := drbg.New(crypto.SHA512, []byte("seeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeed"), nil, []byte("runtime scheduling bnechmark"))
	if err != nil {
		panic(err)
	}
	rng := rand.New(mathrand.New(rngSrc))
	values := prepareTxs(b, rng, 10000)

	b.Run("BenchmarkNoOpDispatch", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			noOpTd := &noOpDispatcher{
				scheduler: scheduler,
			}

			benchmarkScheduleTransactions(b, rng, noOpTd, scheduler, values)
		}
	})

	b.Run("BenchmarkDelayDispatch", func(b *testing.B) {
		for n := 0; n < b.N; n++ {
			delayTd := &delayDispatcher{
				rng: rng,
				delay: func(rng *rand.Rand) time.Duration {
					return time.Duration(rand.Intn(100000)) * time.Microsecond
				},
				scheduler: scheduler,
			}

			benchmarkScheduleTransactions(b, rng, delayTd, scheduler, values)
		}
	})
}

func benchmarkScheduleTransactions(b *testing.B, rng *rand.Rand, dispatcher benchmarkingDispatcher, scheduler api.Scheduler, values [][]byte) {
	waitForClear := func(dispatcher benchmarkingDispatcher, scheduler api.Scheduler) {
		// Wait for queue to empty out.
		for {
			if scheduler.UnscheduledSize() == 0 {
				break
			}
			dispatcher.Dispatch(scheduler.GetBatch(true))
		}
	}

	// Submit transactions.
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func(v []byte, wg *sync.WaitGroup) {
			defer wg.Done()
			err := scheduler.QueueTx(v)
			if err != nil {
				panic(err)
			}
			dispatcher.Dispatch(scheduler.GetBatch(false))
		}(v, &wg)
	}
	wg.Wait()

	// Wait that queue clears.
	waitForClear(dispatcher, scheduler)
}

func prepareTxs(b *testing.B, rng *rand.Rand, n uint64) [][]byte {
	b.StopTimer()

	values := [][]byte{}
	for i := uint64(0); i < n; i++ {
		b := make([]byte, rng.Intn(128/2)+1)
		rng.Read(b)
		values = append(values, b)
	}
	b.StartTimer()

	return values
}
