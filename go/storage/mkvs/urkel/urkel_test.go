package urkel

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/dgraph-io/badger"
	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	db "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	badgerDb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/badger"
	levelDb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/leveldb"
	lruDb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/lru"
	memoryDb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/memory"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

const (
	insertItems  = 1000
	allItemsRoot = "5f101fe53bb5d0b17e8bcdd07e08078c66627e2bd0d8a9f64e967eb67fe7d420"
)

var (
	_ syncer.ReadSyncer = (*dummySerialSyncer)(nil)
)

type dummySerialSyncer struct {
	backing syncer.ReadSyncer
}

func (s *dummySerialSyncer) GetSubtree(ctx context.Context, root hash.Hash, id node.ID, maxDepth uint8) (*syncer.Subtree, error) {
	obj, err := s.backing.GetSubtree(ctx, root, id, maxDepth)
	if err != nil {
		return nil, err
	}
	bytes, err := obj.MarshalBinary()
	if err != nil {
		return nil, err
	}
	st := &syncer.Subtree{}
	err = st.UnmarshalBinary(bytes)
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *dummySerialSyncer) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*syncer.Subtree, error) {
	obj, err := s.backing.GetPath(ctx, root, key, startDepth)
	if err != nil {
		return nil, err
	}
	bytes, err := obj.MarshalBinary()
	if err != nil {
		return nil, err
	}
	st := &syncer.Subtree{}
	err = st.UnmarshalBinary(bytes)
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (s *dummySerialSyncer) GetNode(ctx context.Context, root hash.Hash, id node.ID) (node.Node, error) {
	obj, err := s.backing.GetNode(ctx, root, id)
	if err != nil {
		return nil, err
	}
	bytes, err := obj.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return node.UnmarshalBinary(bytes)
}

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
	require.Equal(t, log, writelog.WriteLog{writelog.LogEntry{Key: keyZero, Value: valueZero}})
	require.Equal(t, log[0].Type(), writelog.LogInsert)

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
	require.Equal(t, log, writelog.WriteLog{writelog.LogEntry{Key: keyOne, Value: valueOne}})
	require.Equal(t, log[0].Type(), writelog.LogInsert)

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
	require.Equal(t, log, writelog.WriteLog{writelog.LogEntry{Key: keyOne, Value: nil}})
	require.Equal(t, log[0].Type(), writelog.LogDelete)

	// Test close.
	tree.Close()

	err = tree.Insert(ctx, keyZero, valueZero)
	require.Error(t, err, "Insert after Close")
	require.Equal(t, err, ErrClosed, "Insert must return ErrClosed after Close")

	_, err = tree.Get(ctx, keyZero)
	require.Error(t, err, "Get after Close")
	require.Equal(t, err, ErrClosed, "Get must return ErrClosed after Close")

	err = tree.Remove(ctx, keyZero)
	require.Error(t, err, "Remove after Close")
	require.Equal(t, err, ErrClosed, "Remove must return ErrClosed after Close")

	_, _, err = tree.Commit(ctx)
	require.Error(t, err, "Commit after Close")
	require.Equal(t, err, ErrClosed, "Commit must return ErrClosed after Close")
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
	require.Equal(t, 558, stats.PathFetches, "path fetches (no prefetch)")
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
	require.Equal(t, 416, stats.PathFetches, "path fetches (no prefetch)")
	require.Equal(t, 0, stats.ValueFetches, "value fetches (with prefetch)")
}

func testSyncerGetPath(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	keys, values := generateKeyValuePairs()

	testGetPath := func(t *testing.T, tree *Tree, root hash.Hash) {
		for i := 0; i < len(keys); i++ {
			key := hashKey(keys[i])
			st, err := tree.GetPath(ctx, root, key, 0)
			require.NoErrorf(t, err, "GetPath")

			// Reconstructed subtree should contain key as leaf node.
			var foundLeaf bool
			for _, n := range st.FullNodes {
				if ln, ok := n.(*node.LeafNode); ok {
					if ln.Key.Equal(&key) {
						require.EqualValues(t, values[i], ln.Value.Value, "leaf value should be equal")
						foundLeaf = true
						break
					}
				}
			}
			require.Truef(t, foundLeaf, "subtree should contain target leaf")
		}
	}

	// Test with the base tree.
	tree := New(nil, ndb)
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	t.Run("Base", func(t *testing.T) {
		testGetPath(t, tree, root)
	})

	// Test with a remote tree via the read-syncer interface.
	t.Run("Remote", func(t *testing.T) {
		remoteTree, err := NewWithRoot(ctx, tree, nil, root)
		require.NoError(t, err, "NewWithRoot")

		testGetPath(t, remoteTree, root)
	})
}

func testSyncerRemove(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	var roots []hash.Hash
	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		_, root, err := tree.Commit(ctx)
		require.NoError(t, err, "Commit")
		roots = append(roots, root)
	}

	require.Equal(t, allItemsRoot, roots[len(roots)-1].String())

	remoteTree, err := NewWithRoot(ctx, tree, nil, roots[len(roots)-1])
	require.NoError(t, err, "NewWithRoot")

	for i := len(keys) - 1; i >= 0; i-- {
		err = remoteTree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")
	}

	_, rootHash, err := remoteTree.Commit(ctx)
	require.NoError(t, err, "Commit")
	require.True(t, rootHash.IsEmpty())
}

func testSyncerInsert(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	keys, values := generateKeyValuePairsEx("foo", 100)
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, rootHash, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	remoteTree, err := NewWithRoot(ctx, tree, nil, rootHash)
	require.NoError(t, err, "NewWithRoot")

	keys, values = generateKeyValuePairsEx("bar", 100)
	for i := 0; i < len(keys); i++ {
		err = remoteTree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}
}

func testSyncerNilNodes(t *testing.T, ndb db.NodeDB) {
	var err error

	ctx := context.Background()
	tree := New(nil, nil)

	// Arbitrary sequence of operations. The point is to produce a tree with
	// an internal node where at least one of the children is a null pointer.
	err = tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("carrot"), []byte("stick"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("ping"), []byte("pong"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("moo"), []byte("boo"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("aardvark"), []byte("aah"))
	require.NoError(t, err, "Insert")

	// Verify at least one null pointer somewhere.

	_, root, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	wire := &dummySerialSyncer{
		backing: tree,
	}
	remote, err := NewWithRoot(ctx, wire, nil, root)
	require.NoError(t, err, "NewWithRoot")

	// Now try inserting a k-v pair that will force the tree to traverse through the nil node
	// and dereference it.
	err = remote.Insert(ctx, []byte("insert"), []byte("key"))
	require.NoError(t, err, "Insert")
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
	tree := New(nil, ndb, Capacity(128, 0))

	keys, values := generateKeyValuePairsEx("foo", 150)
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err := tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	keys, values = generateKeyValuePairsEx("foo key 1", 150)
	for i := 0; i < len(keys); i++ {
		err = tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err = tree.Commit(ctx)
	require.NoError(t, err, "Commit")

	stats := tree.Stats(ctx, 0)
	// Only a subset of nodes should remain in cache.
	require.EqualValues(t, 89, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 39, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	// Only a subset of the leaf values should remain in cache.
	require.EqualValues(t, 676, stats.Cache.LeafValueSize, "Cache.LeafValueSize")
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

func testOnCommitHooks(t *testing.T, ndb db.NodeDB) {
	batch := ndb.NewBatch()
	defer batch.Reset()

	var calls []int

	batch.OnCommit(func() {
		calls = append(calls, 1)
	})
	batch.OnCommit(func() {
		calls = append(calls, 2)
	})
	batch.OnCommit(func() {
		calls = append(calls, 3)
	})

	require.True(t, len(calls) == 0, "OnCommit hooks should not fire before commit")

	var emptyRoot hash.Hash
	emptyRoot.Empty()

	err := batch.Commit(emptyRoot)
	require.NoError(t, err, "Commit")
	require.EqualValues(t, calls, []int{1, 2, 3}, "OnCommit hooks should fire in order")
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
	t.Run("SyncerGetPath", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testSyncerGetPath(t, backend)
	})
	t.Run("SyncerRemove", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testSyncerRemove(t, backend)
	})
	t.Run("SyncerInsert", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testSyncerInsert(t, backend)
	})
	t.Run("SyncerNilNodes", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testSyncerNilNodes(t, backend)
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
	t.Run("OnCommitHooks", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testOnCommitHooks(t, backend)
	})
}

func TestUrkelMemoryBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (db.NodeDB, interface{}) {
		// Create a memory-backed Node DB.
		ndb, _ := memoryDb.New()
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
		ndb, err := levelDb.New(dir)
		require.NoError(t, err, "New")

		return ndb, dir
	},
		func(t *testing.T, ndb db.NodeDB, custom interface{}) {
			ndb.Close()

			dir, ok := custom.(string)
			require.True(t, ok, "finiBackend")

			os.RemoveAll(dir)
		})
}

func TestUrkelBadgerBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (db.NodeDB, interface{}) {
		// Create a new random temporary directory under /tmp.
		dir, err := ioutil.TempDir("", "mkvs.test.badger")
		require.NoError(t, err, "TempDir")

		// Create a Badger-backed Node DB.
		ndb, err := badgerDb.New(badger.DefaultOptions(dir).WithLogger(nil))
		require.NoError(t, err, "New")

		return ndb, dir
	},
		func(t *testing.T, ndb db.NodeDB, custom interface{}) {
			ndb.Close()

			dir, ok := custom.(string)
			require.True(t, ok, "finiBackend")

			os.RemoveAll(dir)
		})
}

func TestUrkelLRUBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (db.NodeDB, interface{}) {
		// Create a new random temporary file under /tmp.
		f, err := ioutil.TempFile("", "mkvs.test.lrudb")
		require.NoError(t, err, "TempFile")
		fname := f.Name()
		f.Close()

		// Create a LRU-backed Node DB.
		ndb, err := lruDb.New(16*1024*1024, fname)
		require.NoError(t, err, "New")

		return ndb, fname
	},
		func(t *testing.T, ndb db.NodeDB, custom interface{}) {
			// Save something to test persistence.
			tree := New(nil, ndb)
			persistenceKey := []byte("persistenceTest")
			persistenceVal := []byte("nothing lasts forever")
			err := tree.Insert(context.Background(), persistenceKey, persistenceVal)
			require.NoError(t, err, "Insert")
			_, root, err := tree.Commit(context.Background())
			require.NoError(t, err, "Commit")

			// Close the database (this persists the LRU cache to file).
			ndb.Close()

			// Now try reopening it to see if loading works.
			fname, ok := custom.(string)
			require.True(t, ok, "finiBackend")

			d, derr := lruDb.New(16*1024*1024, fname)
			require.NoError(t, derr, "New (persistence)")

			// Fetch persisted value.
			tree, terr := NewWithRoot(context.Background(), nil, d, root)
			require.NoError(t, terr, "NewWithRoot (persistence)")
			v, verr := tree.Get(context.Background(), persistenceKey)
			require.NoError(t, verr, "Get (persistence)")
			require.Equal(t, persistenceVal, v)

			// OK, we're done, clean up.
			d.Close()
			os.Remove(fname)
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

	st, err := tree.GetSubtree(ctx, root, node.ID{Path: root, Depth: 0}, 10)
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
		ndb, _ := memoryDb.New()
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

func generateKeyValuePairsEx(prefix string, count int) ([][]byte, [][]byte) {
	keys := make([][]byte, count)
	values := make([][]byte, count)
	for i := 0; i < count; i++ {
		keys[i] = []byte(fmt.Sprintf("%skey %d", prefix, i))
		values[i] = []byte(fmt.Sprintf("%svalue %d", prefix, i))
	}

	return keys, values
}

func generateKeyValuePairs() ([][]byte, [][]byte) {
	return generateKeyValuePairsEx("", insertItems)
}
