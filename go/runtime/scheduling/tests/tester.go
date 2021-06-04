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
	err := scheduler.UpdateParameters(
		scheduler.Name(),
		map[transaction.Weight]uint64{
			transaction.WeightCount:     100,
			transaction.WeightSizeBytes: 1000,
		},
	)
	require.NoError(t, err, "UpdateParameters")

	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions should be scheduled")

	// Test QueueTx.
	testTx := transaction.NewCheckedTransaction([]byte("hello world"), 10, make(map[transaction.Weight]uint64))
	err = scheduler.QueueTx(testTx)
	require.NoError(t, err, "QueueTx(testTx)")
	require.True(t, scheduler.IsQueued(testTx.Hash()), "IsQueued(tx)")

	// Test GetBatch.
	batch := scheduler.GetBatch(false)
	require.Empty(t, batch, "non-forced GetBatch should not return any transactions")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "transaction should remain in the queue")
	require.True(t, scheduler.IsQueued(testTx.Hash()), "IsQueued(tx)")

	batch = scheduler.GetBatch(true)
	require.EqualValues(t, []*transaction.CheckedTransaction{testTx}, batch, "transaction should be returned")
	require.True(t, scheduler.IsQueued(testTx.Hash()), "IsQueued(tx)")

	// Test RemoveTxBatch.
	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	err = scheduler.RemoveTxBatch(hashes)
	require.NoError(t, err, "RemoveTxBatch")
	require.False(t, scheduler.IsQueued(testTx.Hash()), "IsQueued(tx)")
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "no transactions should remain")

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
		scheduler.Name(),
		map[transaction.Weight]uint64{
			transaction.WeightCount:     1,
			transaction.WeightSizeBytes: 10000,
		},
	)
	require.NoError(t, err, "UpdateParameters")

	// TestTx should remain queued.
	require.True(t, scheduler.IsQueued(testTx.Hash()), "transaction should remain in the queue")
	require.EqualValues(t, 1, scheduler.UnscheduledSize(), "transaction should remain in the queue")
	// Re-quining should have no effect.
	require.NoError(t, scheduler.QueueTx(testTx))

	// Make sure transaction gets scheduled now.
	batch = scheduler.GetBatch(false)
	require.Len(t, batch, 1, "transaction should be returned")

	// Remove after update.
	hashes = make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	require.NoError(t, scheduler.RemoveTxBatch(hashes))
	// Make sure queue is empty now.
	batch = scheduler.GetBatch(true)
	require.Empty(t, batch, "queue should be empty")

	// Test update clear transactions.
	// Update configuration back to BatchSize=10.
	err = scheduler.UpdateParameters(
		scheduler.Name(),
		map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 10000,
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
		scheduler.Name(),
		map[transaction.Weight]uint64{
			transaction.WeightCount:     10,
			transaction.WeightSizeBytes: 1,
		},
	)
	require.NoError(t, err, "UpdateParameters")

	// Make sure is removed from the pool.
	batch = scheduler.GetBatch(true)
	require.Empty(t, batch, "queue should be empty")
	require.EqualValues(t, 0, scheduler.UnscheduledSize(), "transaction should get removed on update")

	// Test invalid udpate.
	err = scheduler.UpdateParameters(
		"invalid",
		map[transaction.Weight]uint64{},
	)
	require.Error(t, err, "UpdateParameters invalid udpate")

	// Test priorities.
	err = scheduler.UpdateParameters(
		scheduler.Name(),
		map[transaction.Weight]uint64{
			transaction.WeightCount:     1,
			transaction.WeightSizeBytes: 1000,
		},
	)
	require.NoError(t, err, "UpdateParameters")
	txs := make([]*transaction.CheckedTransaction, 50)
	perm := rand.Perm(50)
	for i := 0; i < 50; i++ {
		txs[i] = transaction.NewCheckedTransaction([]byte(fmt.Sprintf("tx-%d", i)), uint64(perm[i]), map[transaction.Weight]uint64{})
		require.NoError(t, scheduler.QueueTx(txs[i]))
	}
	returned := make([]*transaction.CheckedTransaction, 50)
	prios := make([]uint64, 50)
	for i := 0; i < 50; i++ {
		returned[i] = scheduler.GetBatch(false)[0]
		prios[i] = returned[i].Priority()
		require.NoError(t, scheduler.RemoveTxBatch([]hash.Hash{returned[i].Hash()}))
	}
	require.ElementsMatch(t, txs, returned, "all transactions should be returned")
	require.IsDecreasing(t, prios, "transactions should be sorted by priority")
}

type benchmarkingDispatcher interface {
	Dispatch(batch []*transaction.CheckedTransaction)
	DispatchedSize() int
}

type noOpDispatcher struct {
	DispatchedBatches []*transaction.CheckedTransaction
	scheduler         api.Scheduler
}

func (t *noOpDispatcher) Dispatch(batch []*transaction.CheckedTransaction) {
	if len(batch) == 0 {
		return
	}
	t.DispatchedBatches = append(t.DispatchedBatches, batch...)
	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	_ = t.scheduler.RemoveTxBatch(hashes)
}

func (t *noOpDispatcher) DispatchedSize() int {
	return len(t.DispatchedBatches)
}

type delayDispatcher struct {
	rng               *rand.Rand
	delay             func(*rand.Rand) time.Duration
	DispatchedBatches []*transaction.CheckedTransaction
	scheduler         api.Scheduler
}

func (t *delayDispatcher) Dispatch(batch []*transaction.CheckedTransaction) {
	if len(batch) == 0 {
		return
	}
	<-time.After(t.delay(t.rng))
	t.DispatchedBatches = append(t.DispatchedBatches, batch...)
	hashes := make([]hash.Hash, len(batch))
	for i, tx := range batch {
		hashes[i] = tx.Hash()
	}
	_ = t.scheduler.RemoveTxBatch(hashes)
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

func benchmarkScheduleTransactions(b *testing.B, rng *rand.Rand, dispatcher benchmarkingDispatcher, scheduler api.Scheduler, values []*transaction.CheckedTransaction) {
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
		go func(v *transaction.CheckedTransaction, wg *sync.WaitGroup) {
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

func prepareTxs(b *testing.B, rng *rand.Rand, n uint64) []*transaction.CheckedTransaction {
	b.StopTimer()

	values := make([]*transaction.CheckedTransaction, n)
	for i := uint64(0); i < n; i++ {
		b := make([]byte, rng.Intn(128/2)+1)
		rng.Read(b)
		values[i] = transaction.RawCheckedTransaction(b)
	}
	b.StartTimer()

	return values
}
