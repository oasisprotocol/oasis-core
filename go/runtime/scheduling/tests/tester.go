// Package tests is a collection of worker test cases.
package tests

import (
	"crypto"
	"errors"
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

type testDispatcher struct {
	ShouldFail        bool
	DispatchedBatches []transaction.RawBatch
	scheduler         api.Scheduler
}

func (t *testDispatcher) Clear() {
	t.DispatchedBatches = []transaction.RawBatch{}
}

func (t *testDispatcher) Dispatch(batch transaction.RawBatch) error {
	if t.ShouldFail {
		return errors.New("dispatch failed")
	}
	t.DispatchedBatches = append(t.DispatchedBatches, batch)
	_ = t.scheduler.RemoveTxBatch(batch)
	return nil
}

// SchedulerImplementationTests runs the scheduler implementation tests.
func SchedulerImplementationTests(
	t *testing.T,
	scheduler api.Scheduler,
) {
	td := testDispatcher{ShouldFail: false, scheduler: scheduler}

	err := scheduler.Initialize(&td)
	require.NoError(t, err, "Initialize(td)")

	// Run the test cases.
	t.Run("ScheduleTxs", func(t *testing.T) {
		testScheduleTransactions(t, &td, scheduler)
	})
}

func testScheduleTransactions(t *testing.T, td *testDispatcher, scheduler api.Scheduler) {
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions should be scheduled")

	// Test ScheduleTx.
	testTx := []byte("hello world")
	txBytes := hash.NewFromBytes(testTx)
	err := scheduler.ScheduleTx(testTx)
	require.NoError(t, err, "ScheduleTx(testTx)")
	require.True(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")

	// Test FlushTx.
	err = scheduler.Flush(false)
	require.NoError(t, err, "Flush(force=false)")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "transaction should remain unscheduled after a non-forced flush")
	require.True(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")
	err = scheduler.Flush(true)
	require.NoError(t, err, "Flush(force=true)")
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions should be scheduled after flushing a single tx")
	require.Equal(t, 1, len(td.DispatchedBatches), "one batch should be dispatched")
	require.EqualValues(t, transaction.RawBatch{testTx}, td.DispatchedBatches[0], "transaction should be dispatched")
	require.False(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")

	// Test with a Failing Dispatcher.
	td.Clear()
	td.ShouldFail = true
	testTx2 := []byte("hello world2")
	tx2Bytes := hash.NewFromBytes(testTx2)

	err = scheduler.ScheduleTx(testTx2)
	require.NoError(t, err, "ScheduleTx(testTx2)")
	require.True(t, scheduler.IsQueued(tx2Bytes), "IsQueued(tx)")
	require.False(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")

	err = scheduler.Flush(true)
	require.Error(t, err, "dispatch failed", "Flush(force=true)")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "failed dispatch should return tx in the queue")

	// Retry failed transaction with a Working Dispatcher.
	td.ShouldFail = false
	err = scheduler.Flush(true)
	require.NoError(t, err, "Flush(force=true)")
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions after flushing a single tx")
	require.False(t, scheduler.IsQueued(tx2Bytes), "IsQueued(tx)")
	require.Equal(t, 1, len(td.DispatchedBatches), "one batch should be dispatched")
	require.EqualValues(t, transaction.RawBatch{testTx2}, td.DispatchedBatches[0], "transaction should be dispatched")
	td.Clear()

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
	err = scheduler.Flush(true)
	require.NoError(t, err, "Flush(force=true)")
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions after flushing")

	// Test Update configuration.
	// First insert a transaction.
	err = scheduler.ScheduleTx(testTx)
	require.NoError(t, err, "ScheduleTx(testTx)")
	// Make sure transaction doesn't get scheduled.
	err = scheduler.Flush(false)
	require.NoError(t, err, "Flush(force=false)")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "transaction should remain unscheduled after a non-forced flush")
	// Update configuration to BatchSize=1.
	err = scheduler.UpdateParameters(
		registry.TxnSchedulerParameters{
			Algorithm:         scheduler.Name(),
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 10000,
		},
	)
	require.NoError(t, err, "UpdateParameters")
	// Make sure transaction gets scheduled now.
	err = scheduler.Flush(false)
	require.NoError(t, err, "Flush(force=false)")
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "transaction should get scheduled after a non-forced flush")

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
	err = scheduler.ScheduleTx(testTx)
	require.NoError(t, err, "ScheduleTx(testTx)")
	// Make sure transaction is scheduled.
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "one transaction scheduled")
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
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "transaction should get scheduled after a non-forced flush")

	// Test invalid udpate.
	err = scheduler.UpdateParameters(
		registry.TxnSchedulerParameters{
			Algorithm: "invalid",
		},
	)
	require.Error(t, err, "UpdateParameters invalid udpate")
}

type benchmarkingDispatcher interface {
	api.TransactionDispatcher
	DispatchedSize() int
}

type noOpDispatcher struct {
	DispatchedBatches transaction.RawBatch
	scheduler         api.Scheduler
}

func (t *noOpDispatcher) Dispatch(batch transaction.RawBatch) error {
	t.DispatchedBatches = append(t.DispatchedBatches, batch...)
	_ = t.scheduler.RemoveTxBatch(batch)
	return nil
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

func (t *delayDispatcher) Dispatch(batch transaction.RawBatch) error {
	<-time.After(t.delay(t.rng))
	t.DispatchedBatches = append(t.DispatchedBatches, batch...)
	_ = t.scheduler.RemoveTxBatch(batch)
	return nil
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
			err := scheduler.Initialize(noOpTd)
			require.NoError(b, err, "Initialize(noOpTd)")

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
			err := scheduler.Initialize(delayTd)
			require.NoError(b, err, "Initialize(delayTd)")

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
			scheduler.Flush(true)
		}
	}

	// Submit transactions.
	var wg sync.WaitGroup
	for _, v := range values {
		wg.Add(1)
		go func(v []byte, wg *sync.WaitGroup) {
			defer wg.Done()
			err := scheduler.ScheduleTx(v)
			if err != nil {
				panic(err)
			}
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
