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

	"github.com/oasislabs/ekiden/go/common"
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
	allItemsRoot = "67774198b787b4846f67f1cfd1715b4e94d1a75f6caeda08635f8a03932f3413"

	longKey          = "Unlock the potential of your data without compromising security or privacy"
	longValue        = "The platform that puts data privacy first. From sharing medical records, to analyzing personal financial information, to training machine learning models, the Oasis platform supports applications that use even the most sensitive data without compromising privacy or performance."
	allLongItemsRoot = "0a80a0cf285f9eedec0339372c0ae25190ed75809a0799ab75a593d783ddef00"
)

var (
	testNs common.Namespace

	_ syncer.ReadSyncer = (*dummySerialSyncer)(nil)
)

type dummySerialSyncer struct {
	backing syncer.ReadSyncer
}

// writeLogToMap is a helper for getting unordered WriteLog.
func writeLogToMap(wl writelog.WriteLog) map[string]string {
	writeLogSet := make(map[string]string)
	for _, elt := range wl {
		writeLogSet[string(elt.Key)] = string(elt.Value)
	}

	return writeLogSet
}

func (s *dummySerialSyncer) GetSubtree(ctx context.Context, root node.Root, id node.ID, maxDepth node.Depth) (*syncer.Subtree, error) {
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

func (s *dummySerialSyncer) GetPath(ctx context.Context, root node.Root, key node.Key, startDepth node.Depth) (*syncer.Subtree, error) {
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

func (s *dummySerialSyncer) GetNode(ctx context.Context, root node.Root, id node.ID) (node.Node, error) {
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
	valueZeroAlt := []byte("baz")
	keyOne := []byte("moo")
	valueOne := []byte("foo")
	valueOneAlt := []byte("boo")

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

	log, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.Equal(t, "c86e7119b52682fea21319c9c747e2197012b49f5050fce5e4aa82e5ced36236", root.String())
	require.Equal(t, writeLogToMap(writelog.WriteLog{writelog.LogEntry{Key: keyZero, Value: valueZero}}), writeLogToMap(log))
	require.Equal(t, log[0].Type(), writelog.LogInsert)

	// Check overwriting modifications.
	err = tree.Insert(ctx, keyOne, valueOne)
	require.NoError(t, err, "Insert")
	value, err = tree.Get(ctx, keyOne)
	require.NoError(t, err, "Get")
	require.Equal(t, valueOne, value)

	err = tree.Insert(ctx, keyZero, valueZeroAlt)
	require.NoError(t, err, "Insert")
	value, err = tree.Get(ctx, keyZero)
	require.NoError(t, err, "Get")
	require.Equal(t, valueZeroAlt, value)
	value, err = tree.Get(ctx, keyOne)
	require.NoError(t, err, "Get")
	require.Equal(t, valueOne, value)
	err = tree.Remove(ctx, keyOne)
	require.NoError(t, err, "Remove")
	err = tree.Remove(ctx, keyOne)
	require.NoError(t, err, "Remove")
	value, err = tree.Get(ctx, keyOne)
	require.NoError(t, err, "Get")
	require.Nil(t, value)
	value, err = tree.Get(ctx, keyZero)
	require.NoError(t, err, "Get")
	require.Equal(t, valueZeroAlt, value)
	err = tree.Insert(ctx, keyOne, valueOneAlt)
	require.NoError(t, err, "Insert")
	value, err = tree.Get(ctx, keyZero)
	require.NoError(t, err, "Get")
	require.Equal(t, valueZeroAlt, value)
	value, err = tree.Get(ctx, keyOne)
	require.NoError(t, err, "Get")
	require.Equal(t, valueOneAlt, value)
	err = tree.Insert(ctx, keyZero, valueZero)
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, keyOne, valueOne)
	require.NoError(t, err, "Insert")

	// Tree now has key_zero and key_one and should hash as if the mangling didn't happen.
	log, root, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.Equal(t, "573e3d24a5e6cf48a390910c31c7166aa40414037380bc77d648b3967b1e124f", root.String())
	require.Equal(t, writeLogToMap(writelog.WriteLog{writelog.LogEntry{Key: keyOne, Value: valueOne}, writelog.LogEntry{Key: keyZero, Value: valueZero}}), writeLogToMap(log))
	require.Equal(t, writelog.LogInsert, log[0].Type())
	require.Equal(t, writelog.LogInsert, log[1].Type())

	// Create a new tree backed by the same database.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      root,
	})
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

	log, root, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.Equal(t, "c86e7119b52682fea21319c9c747e2197012b49f5050fce5e4aa82e5ced36236", root.String())
	require.Equal(t, writeLogToMap(writelog.WriteLog{writelog.LogEntry{Key: keyOne, Value: nil}}), writeLogToMap(log))
	require.Equal(t, writelog.LogDelete, log[0].Type())

	_, err = tree.CommitKnown(ctx, node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      root,
	})
	require.NoError(t, err, "CommitKnown")

	var bogusRoot hash.Hash
	bogusRoot.FromBytes([]byte("bogus root"))
	_, err = tree.CommitKnown(ctx, node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      bogusRoot,
	})
	require.Error(t, err, "CommitKnown")

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

	_, _, err = tree.Commit(ctx, testNs, 0)
	require.Error(t, err, "Commit after Close")
	require.Equal(t, err, ErrClosed, "Commit must return ErrClosed after Close")
}

func testLongKeys(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb, Capacity(0, 512))

	// First insert keys 0..n and remove them in order n..0.
	var roots []hash.Hash
	keys, values := generateLongKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		_, root, err := tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		roots = append(roots, root)
	}

	for i := 0; i < len(keys); i++ {
		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value, "get at index %d", i)
	}

	require.Equal(t, allLongItemsRoot, roots[len(roots)-1].String())

	for i := len(keys) - 1; i > 0; i-- {
		err := tree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")

		// Key should not exist anymore.
		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value)

		_, root, err := tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		require.Equal(t, roots[i-1], root, "root after removal at index %d", i)
	}

	err := tree.Remove(ctx, keys[0])
	require.NoError(t, err, "Remove")

	_, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, root.IsEmpty())
}

func testEmptyKeys(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	testEmptyKeyInsert := func(t *testing.T, ctx context.Context, tree *Tree) {
		emptyKey := node.Key("")
		emptyValue := []byte("empty value")

		err := tree.Insert(ctx, emptyKey, emptyValue)
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, emptyKey)
		require.NoError(t, err, "Get")
		require.Equal(t, emptyValue, value, "empty value after insert")
	}

	testEmptyKeyRemove := func(t *testing.T, ctx context.Context, tree *Tree) {
		emptyKey := node.Key("")

		err := tree.Remove(ctx, emptyKey)
		require.NoError(t, err, "Remove")

		value, err := tree.Get(ctx, emptyKey)
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value, "empty value after remove")
	}

	testZerothDiscriminatorBitInsert := func(t *testing.T, ctx context.Context, tree *Tree) {
		key1 := node.Key{0x7f, 0xab}
		key2 := node.Key{0xff, 0xab}
		value1 := []byte("value 1")
		value2 := []byte("value 2")

		err := tree.Insert(ctx, key1, value1)
		require.NoError(t, err, "Insert")
		err = tree.Insert(ctx, key2, value2)
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, key1)
		require.NoError(t, err, "Get")
		require.Equal(t, value1, value, "empty value after insert")

		value, err = tree.Get(ctx, key2)
		require.NoError(t, err, "Get")
		require.Equal(t, value2, value, "empty value after insert")
	}

	testZerothDiscriminatorBitRemove := func(t *testing.T, ctx context.Context, tree *Tree) {
		key1 := node.Key{0x7f, 0xab}
		key2 := node.Key{0xff, 0xab}

		err := tree.Remove(ctx, key1)
		require.NoError(t, err, "Remove")
		value, err := tree.Get(ctx, key1)
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value, "empty value after remove")

		err = tree.Remove(ctx, key2)
		require.NoError(t, err, "Remove")
		value, err = tree.Get(ctx, key2)
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value, "empty value after remove")
	}

	testEmptyKeyInsert(t, ctx, tree)
	testEmptyKeyRemove(t, ctx, tree)
	testZerothDiscriminatorBitInsert(t, ctx, tree)
	testZerothDiscriminatorBitRemove(t, ctx, tree)

	testEmptyKeyInsert(t, ctx, tree)
	testZerothDiscriminatorBitInsert(t, ctx, tree)

	// First insert keys 0..n and remove them in order n..0.
	var roots []hash.Hash
	keys, values := generateKeyValuePairsEx("", 11)
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)

		testEmptyKeyRemove(t, ctx, tree)
		testEmptyKeyInsert(t, ctx, tree)
		testZerothDiscriminatorBitRemove(t, ctx, tree)
		testZerothDiscriminatorBitInsert(t, ctx, tree)

		_, root, err := tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		roots = append(roots, root)
	}

	for i := len(keys) - 1; i > 0; i-- {
		err := tree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")

		// Key should not exist anymore.
		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value)

		testEmptyKeyRemove(t, ctx, tree)
		testEmptyKeyInsert(t, ctx, tree)
		testZerothDiscriminatorBitRemove(t, ctx, tree)
		testZerothDiscriminatorBitInsert(t, ctx, tree)

		_, root, err := tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		require.Equal(t, roots[i-1], root, "root after removal at index %d", i)
	}

	testEmptyKeyRemove(t, ctx, tree)
	testZerothDiscriminatorBitRemove(t, ctx, tree)

	err := tree.Remove(ctx, keys[0])
	require.NoError(t, err, "Remove")

	_, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, root.IsEmpty())

	testEmptyKeyInsert(t, ctx, tree)
	testZerothDiscriminatorBitInsert(t, ctx, tree)

	// Now re-insert keys n..0, remove them in order 0..n.
	for i := len(keys) - 1; i >= 0; i-- {
		err = tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		var value []byte
		value, err = tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value, "value after insert at index %d", i)

		testEmptyKeyRemove(t, ctx, tree)
		testEmptyKeyInsert(t, ctx, tree)
		testZerothDiscriminatorBitRemove(t, ctx, tree)
		testZerothDiscriminatorBitInsert(t, ctx, tree)

		_, _, err = tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
	}

	for i := 0; i < len(keys); i++ {
		err = tree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")

		// Key should not exist anymore.
		var value []byte
		value, err = tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value)

		testEmptyKeyRemove(t, ctx, tree)
		testEmptyKeyInsert(t, ctx, tree)
		testZerothDiscriminatorBitRemove(t, ctx, tree)
		testZerothDiscriminatorBitInsert(t, ctx, tree)

		_, _, err = tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
	}

	testEmptyKeyRemove(t, ctx, tree)
	testZerothDiscriminatorBitRemove(t, ctx, tree)

	_, _, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, root.IsEmpty())
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

	_, root, err := tree.Commit(ctx, testNs, 0)
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

		_, _, err = tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
	}

	_, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.Equal(t, allItemsRoot, root.String())
}

func testRemove(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	// First insert keys 0..n and remove them in order n..0.
	var roots []hash.Hash
	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)

		_, root, err := tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		roots = append(roots, root)
	}

	require.Equal(t, allItemsRoot, roots[len(roots)-1].String())

	for i := len(keys) - 1; i > 0; i-- {
		err := tree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")

		// Key should not exist anymore.
		value, err := tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value)

		_, root, err := tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		require.Equal(t, roots[i-1], root, "root after removal at index %d", i)
	}

	err := tree.Remove(ctx, keys[0])
	require.NoError(t, err, "Remove")

	_, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, root.IsEmpty())

	// Now re-insert keys n..0, remove them in order 0..n.
	for i := len(keys) - 1; i >= 0; i-- {
		err = tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")

		var value []byte
		value, err = tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value, "value after insert at index %d", i)

		_, _, err = tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
	}

	for i := 0; i < len(keys); i++ {
		err = tree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")

		// Key should not exist anymore.
		var value []byte
		value, err = tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value)

		_, _, err = tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
	}

	_, _, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, root.IsEmpty())
}

func testSyncerBasic(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb, Capacity(0, 0))

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.Equal(t, allItemsRoot, root.String())

	// Create a "remote" tree that talks to the original tree via the
	// syncer interface. First try with no prefetching and then with
	// prefetching.

	r := node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      root,
	}

	stats := syncer.NewStatsCollector(tree)
	remoteTree, err := NewWithRoot(ctx, stats, nil, r, Capacity(0, 0))
	require.NoError(t, err, "NewWithRoot")

	for i := 0; i < len(keys); i++ {
		var value []byte
		value, err = remoteTree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)
	}

	require.Equal(t, 0, stats.SubtreeFetches, "subtree fetches (no prefetch)")
	require.Equal(t, 0, stats.NodeFetches, "node fetches (no prefetch)")
	require.Equal(t, 637, stats.PathFetches, "path fetches (no prefetch)")
	require.Equal(t, 0, stats.ValueFetches, "value fetches (no prefetch)")

	stats = syncer.NewStatsCollector(tree)
	remoteTree, err = NewWithRoot(ctx, stats, nil, r, PrefetchDepth(2))
	require.NoError(t, err, "NewWithRoot")

	for i := 0; i < len(keys); i++ {
		value, err := remoteTree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)
	}

	require.Equal(t, 1, stats.SubtreeFetches, "subtree fetches (with prefetch)")
	require.Equal(t, 0, stats.NodeFetches, "node fetches (with prefetch)")
	require.Equal(t, 634, stats.PathFetches, "path fetches (with prefetch)")
	require.Equal(t, 0, stats.ValueFetches, "value fetches (with prefetch)")
}

func testSyncerGetPath(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	keys, values := generateKeyValuePairs()

	testGetPath := func(t *testing.T, tree *Tree, root node.Root) {
		for i := 0; i < len(keys); i++ {
			st, err := tree.GetPath(ctx, root, keys[i], 0)
			require.NoErrorf(t, err, "GetPath")

			// Reconstructed subtree should contain key as leaf node.
			var foundLeaf bool
			for _, n := range st.FullNodes {
				var leaf *node.LeafNode
				switch nd := n.(type) {
				case *node.InternalNode:
					if nd.LeafNode != nil {
						leaf = nd.LeafNode.Node.(*node.LeafNode)
					}
				case *node.LeafNode:
					leaf = nd
				}

				if leaf != nil && leaf.Key.Equal(keys[i]) {
					require.EqualValues(t, values[i], leaf.Value.Value, "leaf value should be equal")
					foundLeaf = true
					break
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

	_, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	r := node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      root,
	}

	t.Run("Base", func(t *testing.T) {
		testGetPath(t, tree, r)
	})

	// Test with a remote tree via the read-syncer interface.
	t.Run("Remote", func(t *testing.T) {
		remoteTree, err := NewWithRoot(ctx, tree, nil, r)
		require.NoError(t, err, "NewWithRoot")

		testGetPath(t, remoteTree, r)
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

		_, root, err := tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		roots = append(roots, root)
	}

	root := node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      roots[len(roots)-1],
	}
	remoteTree, err := NewWithRoot(ctx, tree, nil, root)
	require.NoError(t, err, "NewWithRoot")

	for i := len(keys) - 1; i >= 0; i-- {
		err = remoteTree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")
	}

	_, rootHash, err := remoteTree.Commit(ctx, testNs, 0)
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

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root := node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      rootHash,
	}
	remoteTree, err := NewWithRoot(ctx, tree, nil, root)
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

	_, root, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	wire := &dummySerialSyncer{
		backing: tree,
	}
	remote, err := NewWithRoot(ctx, wire, nil, node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      root,
	})
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

	_, _, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	stats := tree.Stats(ctx, 0)
	require.EqualValues(t, 999, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 1000, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	// Only a subset of the leaf values should remain in cache.
	require.EqualValues(t, 508, stats.Cache.LeafValueSize, "Cache.LeafValueSize")
}

func testNodeEviction(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb, Capacity(128, 0))

	keys, values := generateKeyValuePairsEx("foo", 150)
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	keys, values = generateKeyValuePairsEx("foo key 1", 150)
	for i := 0; i < len(keys); i++ {
		err = tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	stats := tree.Stats(ctx, 0)
	// Only a subset of nodes should remain in cache.
	require.EqualValues(t, 67, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 61, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	// Only a subset of the leaf values should remain in cache.
	require.EqualValues(t, 1032, stats.Cache.LeafValueSize, "Cache.LeafValueSize")
}

func testDoubleInsertWithEviction(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb, Capacity(128, 0))

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	keys, values = generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err = tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
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
	err = tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")

	buffer := &bytes.Buffer{}
	tree.Dump(ctx, buffer)
	require.True(t, len(buffer.Bytes()) > 0)

	buffer = &bytes.Buffer{}
	tree.DumpLocal(ctx, buffer, 0)
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
	require.EqualValues(t, 14, stats.MaxDepth, "MaxDepth")
	require.EqualValues(t, 999, stats.InternalNodeCount, "InternalNodeCount")
	require.EqualValues(t, 901, stats.LeafNodeCount, "LeafNodeCount")
	require.EqualValues(t, 8107, stats.LeafValueSize, "LeafValueSize")
	require.EqualValues(t, 99, stats.DeadNodeCount, "DeadNodeCount")
	// Cached node counts will update on commit.
	require.EqualValues(t, 0, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 0, stats.Cache.LeafNodeCount, "Cache.LeafNodeCount")
	// Cached leaf value size will update on commit.
	require.EqualValues(t, 0, stats.Cache.LeafValueSize, "Cache.LeafValueSize")

	_, _, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Values are not counted as cached until they are committed (since
	// they cannot be evicted while uncommitted).
	stats = tree.Stats(ctx, 0)
	require.EqualValues(t, 14, stats.MaxDepth, "MaxDepth")
	require.EqualValues(t, 999, stats.InternalNodeCount, "InternalNodeCount")
	require.EqualValues(t, 901, stats.LeafNodeCount, "LeafNodeCount")
	require.EqualValues(t, 8107, stats.LeafValueSize, "LeafValueSize")
	require.EqualValues(t, 99, stats.DeadNodeCount, "DeadNodeCount")
	require.EqualValues(t, 999, stats.Cache.InternalNodeCount, "Cache.InternalNodeCount")
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

	err := batch.Commit(node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      emptyRoot,
	})
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
	t.Run("LongKeys", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testLongKeys(t, backend)
	})
	t.Run("EmptyKeys", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testEmptyKeys(t, backend)
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
	t.Run("DoubleInsertWithEviction", func(t *testing.T) {
		backend, custom := initBackend(t)
		defer finiBackend(t, backend, custom)
		testDoubleInsertWithEviction(t, backend)
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
			_, root, err := tree.Commit(context.Background(), testNs, 0)
			require.NoError(t, err, "Commit")

			// Close the database (this persists the LRU cache to file).
			ndb.Close()

			// Now try reopening it to see if loading works.
			fname, ok := custom.(string)
			require.True(t, ok, "finiBackend")

			d, derr := lruDb.New(16*1024*1024, fname)
			require.NoError(t, derr, "New (persistence)")

			// Fetch persisted value.
			r := node.Root{
				Namespace: testNs,
				Round:     0,
				Hash:      root,
			}
			tree, terr := NewWithRoot(context.Background(), nil, d, r)
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

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root := node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      rootHash,
	}

	st, err := tree.GetSubtree(ctx, root, node.ID{Path: node.Key{}, BitDepth: 0}, 24)
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
			_, _, _ = tree.Commit(ctx, testNs, 0)
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

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("ekiden urkel test ns"))
	copy(testNs[:], ns[:])
}

func generateLongKeyValuePairs() ([][]byte, [][]byte) {
	keys := make([][]byte, len(longKey))
	values := make([][]byte, len(longKey))
	for i := 0; i < len(longKey); i++ {
		keys[i] = []byte(longKey[0 : i+1])
		values[i] = []byte(longValue)
	}

	return keys, values
}
