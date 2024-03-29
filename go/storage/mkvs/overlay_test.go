package mkvs

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

func TestOverlay(t *testing.T) {
	ctx := context.Background()

	// Generate some items.
	items := writelog.WriteLog{
		writelog.LogEntry{Key: []byte("key"), Value: []byte("first")},
		writelog.LogEntry{Key: []byte("key 1"), Value: []byte("one")},
		writelog.LogEntry{Key: []byte("key 2"), Value: []byte("two")},
		writelog.LogEntry{Key: []byte("key 5"), Value: []byte("five")},
		writelog.LogEntry{Key: []byte("key 8"), Value: []byte("eight")},
		writelog.LogEntry{Key: []byte("key 9"), Value: []byte("nine")},
	}

	tests := []testCase{
		{seek: node.Key("k"), pos: 0},
		{seek: node.Key("key 1"), pos: 1},
		{seek: node.Key("key 3"), pos: 3},
		{seek: node.Key("key 4"), pos: 3},
		{seek: node.Key("key 5"), pos: 3},
		{seek: node.Key("key 6"), pos: 4},
		{seek: node.Key("key 7"), pos: 4},
		{seek: node.Key("key 8"), pos: 4},
		{seek: node.Key("key 9"), pos: 5},
		{seek: node.Key("key A"), pos: -1},
	}

	tree := New(nil, nil, node.RootTypeState)
	defer tree.Close()

	// Create an overlay over an empty tree and insert some items into the overlay.
	overlay := NewOverlay(tree)
	for _, item := range items {
		err := overlay.Insert(ctx, item.Key, item.Value)
		require.NoError(t, err, "Insert")
	}

	// Test that an overlay-only iterator works correctly.
	t.Run("OnlyOverlay/Iterator", func(t *testing.T) {
		it := overlay.NewIterator(ctx)
		defer it.Close()

		testIterator(t, items, it, tests)
	})

	// Insert some items into the underlying tree.
	err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(items))
	require.NoError(t, err, "ApplyWriteLog")

	// Create an overlay.
	overlay = NewOverlay(tree)

	// Test that all keys can be fetched from an empty overlay.
	t.Run("EmptyOverlay/Get", func(t *testing.T) {
		require := require.New(t)

		for _, item := range items {
			var value []byte
			value, err = overlay.Get(ctx, item.Key)
			require.NoError(err, "Get")
			require.Equal(item.Value, value, "value from overlay should be correct")
		}
	})

	// Test that merged iterator works correctly on an empty overlay (it should behave exactly the
	// same as for the inner tree).
	t.Run("EmptyOverlay/Iterator", func(t *testing.T) {
		it := overlay.NewIterator(ctx)
		defer it.Close()

		testIterator(t, items, it, tests)
	})

	// Add some updates to the overlay.
	err = overlay.Remove(ctx, []byte("key 2"))
	require.NoError(t, err, "Remove")
	err = overlay.Insert(ctx, []byte("key 7"), []byte("seven"))
	require.NoError(t, err, "Insert")
	err = overlay.Remove(ctx, []byte("key 5"))
	require.NoError(t, err, "Remove")
	err = overlay.Insert(ctx, []byte("key 5"), []byte("fivey"))
	require.NoError(t, err, "Insert")

	// Make sure updates did not propagate to the inner tree.
	t.Run("Updates/NoPropagation", func(t *testing.T) {
		require := require.New(t)

		var value []byte
		value, err = tree.Get(ctx, []byte("key 2"))
		require.NoError(err, "Get")
		require.Equal([]byte("two"), value, "value in inner tree should be unchanged")
		value, err = tree.Get(ctx, []byte("key 7"))
		require.NoError(err, "Get")
		require.Nil(value, "value should not exist in inner tree")
	})

	// State of overlay after updates.
	items = writelog.WriteLog{
		writelog.LogEntry{Key: []byte("key"), Value: []byte("first")},
		writelog.LogEntry{Key: []byte("key 1"), Value: []byte("one")},
		writelog.LogEntry{Key: []byte("key 5"), Value: []byte("fivey")},
		writelog.LogEntry{Key: []byte("key 7"), Value: []byte("seven")},
		writelog.LogEntry{Key: []byte("key 8"), Value: []byte("eight")},
		writelog.LogEntry{Key: []byte("key 9"), Value: []byte("nine")},
	}

	tests = []testCase{
		{seek: node.Key("k"), pos: 0},
		{seek: node.Key("key 1"), pos: 1},
		{seek: node.Key("key 3"), pos: 2},
		{seek: node.Key("key 4"), pos: 2},
		{seek: node.Key("key 5"), pos: 2},
		{seek: node.Key("key 6"), pos: 3},
		{seek: node.Key("key 7"), pos: 3},
		{seek: node.Key("key 8"), pos: 4},
		{seek: node.Key("key 9"), pos: 5},
		{seek: node.Key("key A"), pos: -1},
	}

	testUpdates := func(name string, overlay OverlayTree, items writelog.WriteLog, tests []testCase) {
		// Test that all keys can be fetched from an updated overlay.
		t.Run(name+"/Updates/Get", func(t *testing.T) {
			require := require.New(t)

			for _, item := range items {
				var value []byte
				value, err = overlay.Get(ctx, item.Key)
				require.NoError(err, "Get")
				require.Equal(item.Value, value, "value from overlay should be correct")
			}
		})

		// Make sure that merged overlay iterator works.
		t.Run(name+"/Updates/Iterator", func(t *testing.T) {
			it := overlay.NewIterator(ctx)
			defer it.Close()

			testIterator(t, items, it, tests)
		})
	}

	// Copy the overlay before commit.
	overlayCopy := overlay.Copy(nil)

	// Test that all the same operations work on both the copy and the original.
	testUpdates("Original", overlay, items, tests)
	testUpdates("Copy", overlayCopy, items, tests)

	// Change the copy to make sure nothing leaks into the original overlay.
	err = overlayCopy.Remove(ctx, []byte("key 7"))
	require.NoError(t, err, "Remove")
	err = overlayCopy.Insert(ctx, []byte("key 55"), []byte("fiftyfive"))
	require.NoError(t, err, "Insert")

	itemsCopy := writelog.WriteLog{
		writelog.LogEntry{Key: []byte("key"), Value: []byte("first")},
		writelog.LogEntry{Key: []byte("key 1"), Value: []byte("one")},
		writelog.LogEntry{Key: []byte("key 5"), Value: []byte("fivey")},
		writelog.LogEntry{Key: []byte("key 55"), Value: []byte("fiftyfive")},
		writelog.LogEntry{Key: []byte("key 8"), Value: []byte("eight")},
		writelog.LogEntry{Key: []byte("key 9"), Value: []byte("nine")},
	}

	testsCopy := []testCase{
		{seek: node.Key("k"), pos: 0},
		{seek: node.Key("key 1"), pos: 1},
		{seek: node.Key("key 3"), pos: 2},
		{seek: node.Key("key 4"), pos: 2},
		{seek: node.Key("key 5"), pos: 2},
		{seek: node.Key("key 6"), pos: 4},
		{seek: node.Key("key 7"), pos: 4},
		{seek: node.Key("key 8"), pos: 4},
		{seek: node.Key("key 9"), pos: 5},
		{seek: node.Key("key A"), pos: -1},
	}

	testUpdates("Original-Recheck", overlay, items, tests)
	testUpdates("Copy-Recheck", overlayCopy, itemsCopy, testsCopy)

	// Commit the overlay.
	innerTree, err := overlay.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, tree, innerTree, "inner tree returned from Commit should be correct")

	// Make sure committing an already committed tree works just as well.
	innerTree, err = overlay.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, tree, innerTree, "inner tree returned from Commit should be correct")

	// Test that all keys can be fetched from an updated tree.
	t.Run("Committed/Get", func(t *testing.T) {
		require := require.New(t)

		for _, item := range items {
			var value []byte
			value, err = tree.Get(ctx, item.Key)
			require.NoError(err, "Get")
			require.Equal(item.Value, value, "value from updated tree should be correct")
		}
	})

	// Make sure that the updated tree is correct.
	t.Run("Committed/Iterator", func(t *testing.T) {
		it := tree.NewIterator(ctx)
		defer it.Close()

		testIterator(t, items, it, tests)
	})

	// Make sure that closing the overlay does not close the inner tree.
	overlay.Close()
	_, err = tree.Get(ctx, []byte("key"))
	require.NoError(t, err, "Get")
}
