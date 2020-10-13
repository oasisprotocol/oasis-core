package simple

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasic(t *testing.T) {
	queue := newIncomingQueue(51, 10, 100)

	err := queue.Add([]byte("hello world"))
	require.NoError(t, err, "Add")

	err = queue.Add([]byte("hello world"))
	require.Error(t, err, "Add error on duplicates")

	err = queue.Add(make([]byte, 200))
	require.Error(t, err, "Add error on oversized calls")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.Add([]byte(fmt.Sprintf("call %d", i)))
		require.NoError(t, err, "Add")
	}

	err = queue.Add([]byte("another call"))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, queue.Size(), "Size")

	batch := queue.GetBatch(false)
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 51, queue.Size(), "Size")

	err = queue.RemoveBatch(batch)
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 41, queue.Size(), "Size")

	require.EqualValues(t, batch[0], []byte("hello world"))
	for i := 0; i < 9; i++ {
		require.EqualValues(t, batch[i+1], []byte(fmt.Sprintf("call %d", i)))
	}

	// Not a duplicate anymore.
	err = queue.Add([]byte("hello world"))
	require.NoError(t, err, "Add")
	require.EqualValues(t, 42, queue.Size(), "Size")

	queue.Clear()
	require.EqualValues(t, 0, queue.Size(), "Size")
}

func TestNoBatchReady(t *testing.T) {
	queue := newIncomingQueue(51, 10, 100)

	err := queue.Add([]byte("hello world"))
	require.NoError(t, err, "Add")

	batch := queue.GetBatch(false)
	require.Empty(t, batch, "GetBatch empty if no batch available")
}

func TestForceBatch(t *testing.T) {
	queue := newIncomingQueue(51, 10, 100)

	err := queue.Add([]byte("hello world"))
	require.NoError(t, err, "Add")

	batch := queue.GetBatch(true)
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, queue.Size(), "Size")

	err = queue.RemoveBatch(batch)
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 0, queue.Size(), "Size")
}

func TestAddBatch(t *testing.T) {
	queue := newIncomingQueue(51, 10, 100)

	err := queue.AddBatch([][]byte{
		[]byte("hello world"),
		[]byte("hello world"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	})
	// AddBatch should notify error about duplicate transaction.
	require.Error(t, err, "AddBatch")
	// Inserting transactions should still succeed.
	require.EqualValues(t, 4, queue.Size(), "Size")

	for i := 0; i < 10; i++ {
		_ = queue.AddBatch([][]byte{
			[]byte(fmt.Sprintf("a %d", i)),
			[]byte(fmt.Sprintf("b %d", i)),
			[]byte(fmt.Sprintf("c %d", i)),
			[]byte(fmt.Sprintf("d %d", i)),
			[]byte(fmt.Sprintf("e %d", i)),
		})
	}
	require.True(t, queue.Size() <= 51, "queue must not overflow")
}

func TestRemoveBatch(t *testing.T) {
	queue := newIncomingQueue(51, 10, 100)

	err := queue.RemoveBatch([][]byte{})
	require.NoError(t, err, "RemoveBatch empty queue")

	err = queue.AddBatch([][]byte{
		[]byte("hello world"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	})
	require.NoError(t, err, "AddBatch")
	require.EqualValues(t, 4, queue.Size(), "Size")

	err = queue.RemoveBatch([][]byte{})
	require.NoError(t, err, "RemoveBatch empty batch")
	require.EqualValues(t, 4, queue.Size(), "Size")

	err = queue.RemoveBatch([][]byte{
		[]byte("hello world"),
		[]byte("two"),
	})
	require.NoError(t, err, "RemoveBatch")
	require.EqualValues(t, 2, queue.Size(), "Size")

	err = queue.RemoveBatch([][]byte{
		[]byte("hello world"),
	})
	require.NoError(t, err, "RemoveBatch not existing batch")
	require.EqualValues(t, 2, queue.Size(), "Size")
}
