// Package tests is a collection of worker test cases.
package tests

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/txnscheduler/algorithm/api"
)

type testDispatcher struct {
	ShouldFail        bool
	DispatchedBatches []runtime.Batch
}

func (t *testDispatcher) Clear() {
	t.DispatchedBatches = []runtime.Batch{}
}

func (t *testDispatcher) Dispatch(committeeID hash.Hash, batch runtime.Batch) error {
	if t.ShouldFail {
		return errors.New("dispatch failed")
	}
	t.DispatchedBatches = append(t.DispatchedBatches, batch)
	return nil
}

// AlgorithmImplementationTests runs the txnscheduler algorithm implementation tests.
func AlgorithmImplementationTests(
	t *testing.T,
	algorithm api.Algorithm,
) {
	td := testDispatcher{ShouldFail: false}

	// Initialize Algorithm.
	err := algorithm.Initialize(&td)
	require.NoError(t, err, "Initialize(td)")

	// Simulate an epoch transition.
	epoch := committee.NewMockEpochSnapshot()
	err = algorithm.EpochTransition(epoch)
	require.NoError(t, err, "EpochTransition")

	// Run the test cases.
	t.Run("ScheduleTxs", func(t *testing.T) {
		testScheduleTransactions(t, &td, algorithm)
	})
}

func testScheduleTransactions(t *testing.T, td *testDispatcher, algorithm api.Algorithm) {
	require.Equal(t, 0, algorithm.UnscheduledSize(), "no transactions should be scheduled")

	// Test ScheduleTx.
	testTx := []byte("hello world")
	var txBytes hash.Hash
	txBytes.FromBytes(testTx)
	err := algorithm.ScheduleTx(testTx)
	require.NoError(t, err, "ScheduleTx(testTx)")
	require.True(t, algorithm.IsQueued(txBytes), "IsQueued(tx)")

	// Test FlushTx.
	err = algorithm.Flush()
	require.NoError(t, err, "Flush()")
	require.Equal(t, 0, algorithm.UnscheduledSize(), "no transactions should be scheduled after flushing a single tx")
	require.Equal(t, 1, len(td.DispatchedBatches), "one batch should be dispatched")
	require.EqualValues(t, runtime.Batch{testTx}, td.DispatchedBatches[0], "transaction should be dispatched")
	require.False(t, algorithm.IsQueued(txBytes), "IsQueued(tx)")

	// Test with a Failing Dispatcher.
	td.Clear()
	td.ShouldFail = true
	testTx2 := []byte("hello world2")
	var tx2Bytes hash.Hash
	tx2Bytes.FromBytes(testTx2)

	err = algorithm.ScheduleTx(testTx2)
	require.NoError(t, err, "ScheduleTx(testTx2)")
	require.True(t, algorithm.IsQueued(tx2Bytes), "IsQueued(tx)")
	require.False(t, algorithm.IsQueued(txBytes), "IsQueued(tx)")

	err = algorithm.Flush()
	require.Error(t, err, "dispatch failed", "Flush()")
	require.Equal(t, 1, algorithm.UnscheduledSize(), "failed dispatch should return tx in the queue")

	// Retry failed transaction with a Working Dispatcher.
	td.ShouldFail = false
	err = algorithm.Flush()
	require.NoError(t, err, "Flush()")
	require.Equal(t, 0, algorithm.UnscheduledSize(), "no transactions after flushing a single tx")
	require.False(t, algorithm.IsQueued(tx2Bytes), "IsQueued(tx)")
	require.Equal(t, 1, len(td.DispatchedBatches), "one batch should be dispatched")
	require.EqualValues(t, runtime.Batch{testTx2}, td.DispatchedBatches[0], "transaction should be dispatched")

	td.Clear()
}
