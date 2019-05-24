package urkel

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/internal"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
)

const (
	insertItems  = 1000
	allItemsRoot = "5f101fe53bb5d0b17e8bcdd07e08078c66627e2bd0d8a9f64e967eb67fe7d420"
)

func testBasic(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	keyZero := []byte("foo")
	valueZero := []byte("bar")
	err := tree.Insert(ctx, keyZero, valueZero)
	require.NoError(t, err, "Insert")
	value, err := tree.Get(ctx, keyZero)
	require.NoError(t, err, "Get")
	require.Equal(t, valueZero, value)

	err = tree.Insert(ctx, keyZero, valueZero)
	require.NoError(t, err, "Insert")
	value, err = tree.Get(ctx, keyZero)
	require.NoError(t, err, "Get")
	require.Equal(t, valueZero, value)

	log, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, "f83b5a082f1d05c31aadc863c44df9b2b322b570e47e7528faf484ca2084ad08", root.String())
	require.Equal(t, log, WriteLog{LogEntry{Key: keyZero, Value: valueZero}})
	require.Equal(t, log[0].Type(), LogInsert)

	keyOne := []byte("moo")
	valueOne := []byte("foo")
	err = tree.Insert(ctx, keyOne, valueOne)
	require.NoError(t, err, "Insert")
	value, err = tree.Get(ctx, keyOne)
	require.NoError(t, err, "Get")
	require.Equal(t, valueOne, value)

	log, root, err = tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, "839bb81bff8bc8bb0bee99405a094bcb1d983f9f830cc3e3475e07cb7da4b90c", root.String())
	require.Equal(t, log, WriteLog{LogEntry{Key: keyOne, Value: valueOne}})
	require.Equal(t, log[0].Type(), LogInsert)

	// Create a new tree backed by the same database.
	tree, err = NewWithRoot(ctx, nil, ndb, root)
	require.NoError(t, err, "NewWithRoot")

	value, err = tree.Get(ctx, keyZero)
	require.NoError(t, err, "Get")
	require.Equal(t, valueZero, value)
	value, err = tree.Get(ctx, keyOne)
	require.NoError(t, err, "Get")
	require.Equal(t, valueOne, value)

	err = tree.Remove(ctx, keyOne)
	require.NoError(t, err, "Remove")
	value, err = tree.Get(ctx, keyOne)
	require.NoError(t, err, "Get")
	require.Nil(t, value)

	log, root, err = tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, "f83b5a082f1d05c31aadc863c44df9b2b322b570e47e7528faf484ca2084ad08", root.String())
	require.Equal(t, log, WriteLog{LogEntry{Key: keyOne, Value: nil}})
	require.Equal(t, log[0].Type(), LogDelete)
}

func testInsertCommitBatch(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)
	}

	_, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, allItemsRoot, root.String())
}

func testInsertCommitEach(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)

		_, _, err = tree.Commit(ctx)
		require.NoError(t, err, "Commit")
	}

	_, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, allItemsRoot, root.String())
}

func testRemove(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	var roots []hash.Hash
	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)

		_, root, err := tree.Commit(ctx)
		require.NoError(t, err, "Commit")
		roots = append(roots, root)
	}

	require.Equal(t, allItemsRoot, roots[len(roots)-1].String())

	for i := len(keys) - 1; i > 0; i-- {
		err := tree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")

		_, root, err := tree.Commit(ctx)
		require.NoError(t, err, "Commit")
		require.Equal(t, roots[i-1], root, "root after removal at index %d", i)
	}

	err := tree.Remove(ctx, keys[0])
	require.NoError(t, err, "Remove")

	_, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.True(t, root.IsEmpty())
}

func testSyncerBasic(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.Equal(t, allItemsRoot, root.String())

	// Create a "remote" tree that talks to the original tree via the
	// syncer interface. First try with no prefetching and then with
	// prefetching.

	stats := syncer.NewStatsCollector(tree)
	remoteTree, err := NewWithRoot(ctx, stats, nil, root)
	require.NoError(t, err, "NewWithRoot")

	for i := 0; i < len(keys); i++ {
		var value []byte
		value, err = remoteTree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)
	}

	require.Equal(t, 0, stats.SubtreeFetches, "subtree fetches (no prefetch)")
	require.Equal(t, 0, stats.NodeFetches, "node fetches (no prefetch)")
	require.Equal(t, 1216, stats.PathFetches, "path fetches (no prefetch)")
	require.Equal(t, 0, stats.ValueFetches, "value fetches (no prefetch)")

	stats = syncer.NewStatsCollector(tree)
	remoteTree, err = NewWithRoot(ctx, stats, nil, root, PrefetchDepth(10))
	require.NoError(t, err, "NewWithRoot")

	for i := 0; i < len(keys); i++ {
		value, err := remoteTree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)
	}

	require.Equal(t, 1, stats.SubtreeFetches, "subtree fetches (with prefetch)")
	require.Equal(t, 0, stats.NodeFetches, "node fetches (with prefetch)")
	require.Equal(t, 710, stats.PathFetches, "path fetches (no prefetch)")
	require.Equal(t, 0, stats.ValueFetches, "value fetches (with prefetch)")
}

func testValueEviction(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb, Capacity(0, 512))

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	stats := tree.Stats(ctx, 0)
	require.EqualValues(t, 1470, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 1000, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	// Only a subset of the leaf values should remain in cache.
	require.EqualValues(t, 511, stats.Cache.LeafValueSize, "Cache.LeafValueSize")
}

func testNodeEviction(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb, Capacity(512, 0))

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	stats := tree.Stats(ctx, 0)
	// Only a subset of nodes should remain in cache.
	require.EqualValues(t, 313, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 199, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	// Only a subset of the leaf values should remain in cache.
	require.EqualValues(t, 1770, stats.Cache.LeafValueSize, "Cache.LeafValueSize")
}

func testDebugDump(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	err := tree.Insert(ctx, []byte("foo 1"), []byte("bar 1"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 2"), []byte("bar 2"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 3"), []byte("bar 3"))
	require.NoError(t, err, "Insert")

	buffer := &bytes.Buffer{}
	tree.Dump(ctx, buffer)
	require.True(t, len(buffer.Bytes()) > 0)
}

func testDebugStats(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	stats := tree.Stats(ctx, 0)
	require.EqualValues(t, 20, stats.MaxDepth, "MaxDepth")
	require.EqualValues(t, 1470, stats.InternalNodeCount, "InternalNodeCount")
	require.EqualValues(t, 1000, stats.LeafNodeCount, "LeafNodeCount")
	require.EqualValues(t, 8890, stats.LeafValueSize, "LeafValueSize")
	require.EqualValues(t, 471, stats.DeadNodeCount, "DeadNodeCount")
	// Cached node counts will update on commit.
	require.EqualValues(t, 0, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 0, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	// Cached leaf value size will update on commit.
	require.EqualValues(t, 0, stats.Cache.LeafValueSize, "Cache.LeafValueSize")

	_, _, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	// Values are not counted as cached until they are committed (since
	// they cannot be evicted while uncommitted).
	stats = tree.Stats(ctx, 0)
	require.EqualValues(t, 20, stats.MaxDepth, "MaxDepth")
	require.EqualValues(t, 1470, stats.InternalNodeCount, "InternalNodeCount")
	require.EqualValues(t, 1000, stats.LeafNodeCount, "LeafNodeCount")
	require.EqualValues(t, 8890, stats.LeafValueSize, "LeafValueSize")
	require.EqualValues(t, 471, stats.DeadNodeCount, "DeadNodeCount")
	require.EqualValues(t, 1470, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 1000, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	require.EqualValues(t, 8890, stats.Cache.LeafValueSize, "Cache.LeafValueSize")
}

// TODO: More tests for write logs.
// TODO: More tests with bad syncer outputs.

func testBackend(t *testing.T, initBackend func(t *testing.T) (db.NodeDB, interface{}), finiBackend func(t *testing.T, ndb db.NodeDB, custom interface{})) {
	t.Run("Basic", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testBasic(t, backend)
	})
	t.Run("InsertCommitBatch", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testInsertCommitBatch(t, backend)
	})
	t.Run("InsertCommitEach", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testInsertCommitEach(t, backend)
	})
	t.Run("Remove", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testRemove(t, backend)
	})
	t.Run("SyncerBasic", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testSyncerBasic(t, backend)
	})
	t.Run("ValueEviction", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testValueEviction(t, backend)
	})
	t.Run("NodeEviction", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testNodeEviction(t, backend)
	})
	t.Run("DebugDump", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testDebugDump(t, backend)
	})
	t.Run("DebugStats", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testDebugStats(t, backend)
	})
}

func TestUrkelMemoryBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (db.NodeDB, interface{}) {
		// Create a memory-backed Node DB.
		ndb, _ := db.NewMemoryNodeDB()
		return ndb, nil
	},
		func(t *testing.T, ndb db.NodeDB, custom interface{}) {
			ndb.Close()
		})
}

func TestUrkelLevelDBBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (db.NodeDB, interface{}) {
		// Create a new random temporary directory under /tmp.
		dir, err := ioutil.TempDir("", "mkvs.test.leveldb")
		require.NoError(t, err, "TempDir")

		// Create a LevelDB-backed Node DB.
		ndb, err := db.NewLevelDBNodeDB(dir)
		require.NoError(t, err, "NewLevelDBNodeDB")

		return ndb, dir
	},
		func(t *testing.T, ndb db.NodeDB, custom interface{}) {
			ndb.Close()

			dir, ok := custom.(string)
			require.True(t, ok, "finiBackend")

			os.RemoveAll(dir)
		})
}

func TestSubtreeSerializationSimple(t *testing.T) {
	ctx := context.Background()
	tree := New(nil, nil)

	keyZero := []byte("foo")
	valueZero := []byte("bar")
	keyOne := []byte("moo")
	valueOne := []byte("boo")

	err := tree.Insert(ctx, keyZero, valueZero)
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, keyOne, valueOne)
	require.NoError(t, err, "Insert")

	_, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	st, err := tree.GetSubtree(ctx, root, internal.NodeID{Path: root, Depth: 0}, 10)
	require.NoError(t, err, "GetSubtree")

	binary, err := st.MarshalBinary()
	require.NoError(t, err, "MarshalBinary")

	newSt := &syncer.Subtree{}
	err = newSt.UnmarshalBinary(binary)
	require.NoError(t, err, "UnmarshalBinary")

	// Deserialized nodes are automatically set as clean, so the existing
	// subtree won't match the deserialized one.
	// For now, just compare the root and summaries.
	require.True(t, st.Root.Equal(&newSt.Root))
	require.True(t, len(st.FullNodes) == len(newSt.FullNodes))
	require.True(t, len(st.Summaries) == len(newSt.Summaries))
	for i, summary := range st.Summaries {
		require.True(t, summary.Equal(&newSt.Summaries[i]))
	}
}

func BenchmarkInsertCommitBatch1(b *testing.B) {
	benchmarkInsertBatch(b, 1, true)
}

func BenchmarkInsertCommitBatch10(b *testing.B) {
	benchmarkInsertBatch(b, 10, true)
}

func BenchmarkInsertCommitBatch100(b *testing.B) {
	benchmarkInsertBatch(b, 100, true)
}

func BenchmarkInsertCommitBatch1000(b *testing.B) {
	benchmarkInsertBatch(b, 1000, true)
}

func BenchmarkInsertNoCommitBatch1(b *testing.B) {
	benchmarkInsertBatch(b, 1, false)
}

func BenchmarkInsertNoCommitBatch10(b *testing.B) {
	benchmarkInsertBatch(b, 10, false)
}

func BenchmarkInsertNoCommitBatch100(b *testing.B) {
	benchmarkInsertBatch(b, 100, false)
}

func BenchmarkInsertNoCommitBatch1000(b *testing.B) {
	benchmarkInsertBatch(b, 1000, false)
}

func benchmarkInsertBatch(b *testing.B, numValues int, commit bool) {
	ctx := context.Background()

	for n := 0; n < b.N; n++ {
		ndb, _ := db.NewMemoryNodeDB()
		tree := New(nil, ndb)

		for i := 0; i < numValues; i++ {
			key := []byte(fmt.Sprintf("key %d", i))
			value := []byte(fmt.Sprintf("value %d", i))

			_ = tree.Insert(ctx, key, value)
		}

		if commit {
			_, _, _ = tree.Commit(ctx)
		}
	}
}

func generateKeyValuePairs() ([][]byte, [][]byte) {
	keys := make([][]byte, insertItems)
	values := make([][]byte, insertItems)
	for i := 0; i < insertItems; i++ {
		keys[i] = []byte(fmt.Sprintf("key %d", i))
		values[i] = []byte(fmt.Sprintf("value %d", i))
	}

	return keys, values
}
