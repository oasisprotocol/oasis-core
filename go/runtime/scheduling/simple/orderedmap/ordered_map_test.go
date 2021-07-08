package orderedmap

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOrderedMapBasic(t *testing.T) {
	queue := New(51, 10)

	err := queue.Add([]byte("hello world"))
	require.NoError(t, err, "Add")

	err = queue.Add([]byte("hello world"))
	require.Error(t, err, "Add error on duplicates")

	// Add some more calls.
	for i := 0; i < 50; i++ {
		err = queue.Add([]byte(fmt.Sprintf("call %d", i)))
		require.NoError(t, err, "Add")
	}

	err = queue.Add([]byte("another call"))
	require.Error(t, err, "Add error on queue full")

	require.EqualValues(t, 51, queue.Size(), "Size")

	batch := queue.GetBatch()
	require.EqualValues(t, 10, len(batch), "Batch size")
	require.EqualValues(t, 51, queue.Size(), "Size")

	queue.RemoveBatch(batch)
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

func TestOrderedMapGetBatch(t *testing.T) {
	queue := New(51, 10)

	batch := queue.GetBatch()
	require.EqualValues(t, 0, len(batch), "Batch size")
	require.EqualValues(t, 0, queue.Size(), "Size")

	err := queue.Add([]byte("hello world"))
	require.NoError(t, err, "Add")

	batch = queue.GetBatch()
	require.EqualValues(t, 1, len(batch), "Batch size")
	require.EqualValues(t, 1, queue.Size(), "Size")

	queue.RemoveBatch(batch)
	require.EqualValues(t, 0, queue.Size(), "Size")
}

func TestOrderedMapRemoveBatch(t *testing.T) {
	queue := New(51, 10)

	queue.RemoveBatch([][]byte{})

	for _, tx := range [][]byte{
		[]byte("hello world"),
		[]byte("one"),
		[]byte("two"),
		[]byte("three"),
	} {
		require.NoError(t, queue.Add(tx), "Add")
	}
	require.EqualValues(t, 4, queue.Size(), "Size")

	queue.RemoveBatch([][]byte{})
	require.EqualValues(t, 4, queue.Size(), "Size")

	queue.RemoveBatch([][]byte{
		[]byte("hello world"),
		[]byte("two"),
	})
	require.EqualValues(t, 2, queue.Size(), "Size")

	queue.RemoveBatch([][]byte{
		[]byte("hello world"),
	})
	require.EqualValues(t, 2, queue.Size(), "Size")
}
