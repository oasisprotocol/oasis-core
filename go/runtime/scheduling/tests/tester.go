// Package tests is a collection of worker test cases.
package tests

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

type testDispatcher struct {
	ShouldFail        bool
	DispatchedBatches []transaction.RawBatch
}

func (t *testDispatcher) Clear() {
	t.DispatchedBatches = []transaction.RawBatch{}
}

func (t *testDispatcher) Dispatch(batch transaction.RawBatch) error {
	if t.ShouldFail {
		return errors.New("dispatch failed")
	}
	t.DispatchedBatches = append(t.DispatchedBatches, batch)
	return nil
}

// SchedulerImplementationTests runs the scheduler implementation tests.
func SchedulerImplementationTests(
	t *testing.T,
	scheduler api.Scheduler,
) {
	td := testDispatcher{ShouldFail: false}

	err := scheduler.Initialize(&td)
	require.NoError(t, err, "Initialize(td)")

	// Run the test cases.
	t.Run("ScheduleTxs", func(t *testing.T) {
		testScheduleTransactions(t, &td, scheduler)
	})
}

func testScheduleTransactions(t *testing.T, td *testDispatcher, scheduler api.Scheduler) {
	require.Equal(t, 0, scheduler.UnscheduledSize(), "no transactions should be scheduled")

	// Test ScheduleTx.
	testTx := []byte("hello world")
	txBytes := hash.NewFromBytes(testTx)
	err := scheduler.ScheduleTx(testTx)
	require.NoError(t, err, "ScheduleTx(testTx)")
	require.True(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")

	// Test FlushTx.
	err = scheduler.Flush(false)
	require.NoError(t, err, "Flush(force=false)")
	require.Equal(t, 1, scheduler.UnscheduledSize(), "transaction should remain unscheduled after a non-forced flush")
	require.True(t, scheduler.IsQueued(txBytes), "IsQueued(tx)")
	err = scheduler.Flush(true)
	require.NoError(t, err, "Flush(force=true)")
	require.Equal(t, 0, scheduler.UnscheduledSize(), "no transactions should be scheduled after flushing a single tx")
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
	require.Equal(t, 1, scheduler.UnscheduledSize(), "failed dispatch should return tx in the queue")

	// Retry failed transaction with a Working Dispatcher.
	td.ShouldFail = false
	err = scheduler.Flush(true)
	require.NoError(t, err, "Flush(force=true)")
	require.Equal(t, 0, scheduler.UnscheduledSize(), "no transactions after flushing a single tx")
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
	require.Equal(t, 0, scheduler.UnscheduledSize(), "no transactions after flushing")

	// Test Update configuration.
	// First insert a transaction.
	err = scheduler.ScheduleTx(testTx)
	require.NoError(t, err, "ScheduleTx(testTx)")
	// Make sure transaction doesn't get scheduled.
	err = scheduler.Flush(false)
	require.NoError(t, err, "Flush(force=false)")
	require.Equal(t, 1, scheduler.UnscheduledSize(), "transaction should remain unscheduled after a non-forced flush")
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
	require.Equal(t, 0, scheduler.UnscheduledSize(), "transaction should get scheduled after a non-forced flush")

	// Test invalid udpate.
	err = scheduler.UpdateParameters(
		registry.TxnSchedulerParameters{
			Algorithm: "invalid",
		},
	)
	require.Error(t, err, "UpdateParameters invalid udpate")
}
