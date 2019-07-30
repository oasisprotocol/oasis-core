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
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

const (
	insertItems  = 1000
	allItemsRoot = "a092507adb90fce8d38e8c8663f4db0affa50e47955535bbdb21327a8d9c2532"

	longKey          = "Unlock the potential of your data without compromising security or privacy"
	longValue        = "The platform that puts data privacy first. From sharing medical records, to analyzing personal financial information, to training machine learning models, the Oasis platform supports applications that use even the most sensitive data without compromising privacy or performance."
	allLongItemsRoot = "1aa1b04b41ea1cbf3f5ff839bfb1c21cacddc06b773b94b425d46b673352459b"
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

func (s *dummySerialSyncer) GetPath(ctx context.Context, root node.Root, id node.ID, key node.Key) (*syncer.Subtree, error) {
	obj, err := s.backing.GetPath(ctx, root, id, key)
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
	require.Equal(t, "ebf4bddfa659ceed844b04d62e05c2b8cb5ef1f6d73c6026f63d289b6777ce44", root.String())
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
	require.Equal(t, "5c71b5ed7fe2ea8fd663254fd54d648db8e8f285c5712e943321ca7a6710d8ca", root.String())
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
	require.Equal(t, "ebf4bddfa659ceed844b04d62e05c2b8cb5ef1f6d73c6026f63d289b6777ce44", root.String())
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
			// TODO: Test with different bit depths.
			var id node.ID
			id.Root()

			st, err := tree.GetPath(ctx, root, id, keys[i])
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

func testSyncerRootEmptyLabelNeedsDeref(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	// Add two keys that differ in the first bit so the root will have
	// an empty label.
	err := tree.Insert(ctx, []byte{0xFF}, []byte("foo"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte{0x00}, []byte("bar"))
	require.NoError(t, err, "Insert")

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root := node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      rootHash,
	}

	testGet := func(t *testing.T, tree *Tree) {
		value, err := tree.Get(ctx, []byte{0xFF})
		require.NoError(t, err, "Get")
		require.EqualValues(t, value, []byte("foo"))

		value, err = tree.Get(ctx, []byte{0x00})
		require.NoError(t, err, "Get")
		require.EqualValues(t, value, []byte("bar"))
	}
	testRemove := func(t *testing.T, tree *Tree) {
		err := tree.Remove(ctx, []byte{0xFF})
		require.NoError(t, err, "Remove")
		err = tree.Remove(ctx, []byte{0x00})
		require.NoError(t, err, "Remove")
	}
	testInsert := func(t *testing.T, tree *Tree) {
		err := tree.Insert(ctx, []byte{0xFF, 0xFF}, []byte("foo"))
		require.NoError(t, err, "Insert")
		err = tree.Insert(ctx, []byte{0x00, 0x00}, []byte("bar"))
		require.NoError(t, err, "Insert")
	}

	// Create a remote tree so we will need to deref.

	t.Run("Get", func(t *testing.T) {
		remoteTree, err := NewWithRoot(ctx, tree, nil, root)
		require.NoError(t, err, "NewWithRoot")
		testGet(t, remoteTree)
	})

	t.Run("Remove", func(t *testing.T) {
		remoteTree, err := NewWithRoot(ctx, tree, nil, root)
		require.NoError(t, err, "NewWithRoot")
		testRemove(t, remoteTree)
	})

	t.Run("Insert", func(t *testing.T) {
		remoteTree, err := NewWithRoot(ctx, tree, nil, root)
		require.NoError(t, err, "NewWithRoot")
		testInsert(t, remoteTree)
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

func testVisit(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	keys, values := generateKeyValuePairsEx("", 100)
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	visitedValues := make(map[string]bool)
	err := tree.Visit(ctx, func(ctx context.Context, n node.Node) bool {
		switch nd := n.(type) {
		case *node.LeafNode:
			visitedValues[string(nd.Value.Value)] = true
		}

		return true
	})
	require.NoError(t, err, "Visit")

	// Check that we have visited all values.
	for _, value := range values {
		require.Contains(t, visitedValues, string(value))
	}
}

func testApplyWriteLog(t *testing.T, ndb db.NodeDB) {
	keys, values := generateKeyValuePairsEx("", 100)

	// Insert some items first.
	var writeLog writelog.WriteLog
	for i := range keys {
		writeLog = append(writeLog, writelog.LogEntry{Key: keys[i], Value: values[i]})
	}

	ctx := context.Background()
	tree := New(nil, ndb)
	err := tree.ApplyWriteLog(ctx, db.NewStaticWriteLogIterator(writeLog))
	require.NoError(t, err, "ApplyWriteLog")
	_, _, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	for i := range keys {
		var value []byte
		value, err = tree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.EqualValues(t, values[i], value, "inserted value must be equal")
	}

	// Then remove all the items.
	writeLog = nil
	for i := range keys {
		writeLog = append(writeLog, writelog.LogEntry{Key: keys[i]})
	}

	err = tree.ApplyWriteLog(ctx, db.NewStaticWriteLogIterator(writeLog))
	require.NoError(t, err, "ApplyWriteLog")
	var rootHash hash.Hash
	_, rootHash, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, rootHash.IsEmpty(), "root hash must be empty after removal of all items")
}

func testOnCommitHooks(t *testing.T, ndb db.NodeDB) {
	var emptyRoot hash.Hash
	emptyRoot.Empty()
	root := node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      emptyRoot,
	}

	batch := ndb.NewBatch(testNs, 0, root)
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

	err := batch.Commit(root)
	require.NoError(t, err, "Commit")
	require.EqualValues(t, calls, []int{1, 2, 3}, "OnCommit hooks should fire in order")
}

// TODO: More tests for write logs.
// TODO: More tests with bad syncer outputs.

func testHasRoot(t *testing.T, ndb db.NodeDB) {
	// Test that an empty root is always implicitly present.
	root := node.Root{
		Namespace: testNs,
		Round:     0,
	}
	root.Hash.Empty()
	require.True(t, ndb.HasRoot(root), "HasRoot should return true on empty root")

	// Create a root in round 0.
	ctx := context.Background()
	tree := New(nil, ndb)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	// Finalize round 0.
	err = ndb.Finalize(ctx, testNs, 0, []hash.Hash{rootHash1})
	require.NoError(t, err, "Finalize")

	// Make sure that HasRoot returns true.
	root = node.Root{
		Namespace: testNs,
		Round:     0,
		Hash:      rootHash1,
	}
	require.True(t, ndb.HasRoot(root), "HasRoot should return true for existing root")
	root.Hash.FromBytes([]byte("invalid root"))
	require.False(t, ndb.HasRoot(root), "HasRoot should return false for non-existing root")

	// Create a different root in round 1.
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("goo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	// Finalize round 1.
	err = ndb.Finalize(ctx, testNs, 1, []hash.Hash{rootHash2})
	require.NoError(t, err, "Finalize")

	// Make sure that HasRoot for root hash from round 0 but with
	// round 1 passed returns false.
	root = node.Root{
		Namespace: testNs,
		Round:     1,
		Hash:      rootHash1,
	}
	require.False(t, ndb.HasRoot(root), "HasRoot should return false for non-existing root")
	root.Hash = rootHash2
	require.True(t, ndb.HasRoot(root), "HasRoot should return true for existing root")
}

func testPruneBasic(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	// Create some keys in round 0.
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("moo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	// Test that we cannot prune non-finalized rounds.
	_, err = ndb.Prune(ctx, testNs, 0)
	require.Error(t, err, "Prune should fail for non-finalized rounds")
	require.Equal(t, db.ErrNotFinalized, err)
	// Finalize round 0.
	err = ndb.Finalize(ctx, testNs, 0, []hash.Hash{rootHash1})
	require.NoError(t, err, "Finalize")

	// Remove key in round 1.
	err = tree.Remove(ctx, []byte("foo"))
	require.NoError(t, err, "Remove")
	err = tree.Insert(ctx, []byte("another"), []byte("value"))
	require.NoError(t, err, "Insert")
	_, rootHash2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	// Test that we cannot prune non-finalized rounds.
	_, err = ndb.Prune(ctx, testNs, 1)
	require.Error(t, err, "Prune should fail for non-finalized rounds")
	require.Equal(t, db.ErrNotFinalized, err)
	// Finalize round 1.
	err = ndb.Finalize(ctx, testNs, 1, []hash.Hash{rootHash2})
	require.NoError(t, err, "Finalize")

	// Add some keys in round 2.
	err = tree.Insert(ctx, []byte("blah"), []byte("ugh"))
	require.NoError(t, err, "Insert")
	_, rootHash3, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")
	// Test that we cannot prune non-finalized rounds.
	_, err = ndb.Prune(ctx, testNs, 2)
	require.Error(t, err, "Prune should fail for non-finalized rounds")
	require.Equal(t, db.ErrNotFinalized, err)
	// Finalize round 2.
	err = ndb.Finalize(ctx, testNs, 2, []hash.Hash{rootHash3})
	require.NoError(t, err, "Finalize")

	// Prune round 0.
	pruned, err := ndb.Prune(ctx, testNs, 0)
	require.NoError(t, err, "Prune")
	// Two nodes should have been pruned (root and left child).
	require.EqualValues(t, 2, pruned)

	// Keys must still be available in round 2.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 2, Hash: rootHash3})
	require.NoError(t, err, "NewWithRoot")
	value, err := tree.Get(ctx, []byte("blah"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("ugh"), value)
	value, err = tree.Get(ctx, []byte("moo"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("bar"), value)
	value, err = tree.Get(ctx, []byte("another"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("value"), value)
	// Remove key must be gone.
	value, err = tree.Get(ctx, []byte("foo"))
	require.NoError(t, err, "Get")
	require.Nil(t, value, "removed key must be gone")

	// Round 0 must be gone.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHash1})
	require.NoError(t, err, "NewWithRoot")
	_, err = tree.Get(ctx, []byte("foo"))
	require.Error(t, err, "Get")
}

func testPruneManyRounds(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	const numRounds = 50
	const numPairsPerRound = 50

	for r := 0; r < numRounds; r++ {
		for p := 0; p < numPairsPerRound; p++ {
			key := []byte(fmt.Sprintf("key %d/%d", r, p))
			value := []byte(fmt.Sprintf("value %d/%d", r, p))
			err := tree.Insert(ctx, key, value)
			require.NoError(t, err, "Insert")
		}

		_, rootHash, err := tree.Commit(ctx, testNs, uint64(r))
		require.NoError(t, err, "Commit")
		err = ndb.Finalize(ctx, testNs, uint64(r), []hash.Hash{rootHash})
		require.NoError(t, err, "Finalize")
	}

	// Prune all rounds except the last one.
	var totalPruned int
	for r := 0; r < numRounds-1; r++ {
		pruned, err := ndb.Prune(ctx, testNs, uint64(r))
		require.NoError(t, err, "Prune")
		totalPruned += pruned
	}

	// Check that the latest version has all the keys.
	for r := 0; r < numRounds; r++ {
		for p := 0; p < numPairsPerRound; p++ {
			key := []byte(fmt.Sprintf("key %d/%d", r, p))
			value, err := tree.Get(ctx, key)
			require.NoError(t, err, "Get")
			require.EqualValues(t, value, fmt.Sprintf("value %d/%d", r, p))
		}
	}

	// We must have pruned some.
	require.True(t, totalPruned > 0, "pruning must have pruned something")
}

func testPruneCheckpoints(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()
	tree := New(nil, ndb)

	const numRounds = 50
	const numPairsPerRound = 50
	const checkpointEvery = 10

	var roots []hash.Hash
	for r := 0; r < numRounds; r++ {
		for p := 0; p < numPairsPerRound; p++ {
			key := []byte(fmt.Sprintf("key %d/%d", r, p))
			value := []byte(fmt.Sprintf("value %d/%d", r, p))
			err := tree.Insert(ctx, key, value)
			require.NoError(t, err, "Insert")
		}

		_, rootHash, err := tree.Commit(ctx, testNs, uint64(r))
		require.NoError(t, err, "Commit")
		err = ndb.Finalize(ctx, testNs, uint64(r), []hash.Hash{rootHash})
		require.NoError(t, err, "Finalize")
		roots = append(roots, rootHash)
	}

	// Prune all non-checkpoint rounds.
	var totalPruned int
	for r := 0; r < numRounds-1; r++ {
		if r%checkpointEvery == 0 {
			continue
		}

		pruned, err := ndb.Prune(ctx, testNs, uint64(r))
		require.NoError(t, err, "Prune")
		totalPruned += pruned
	}

	// Check that checkpoints have all the keys.
	for r := 0; r < numRounds; r++ {
		if r%checkpointEvery != 0 {
			continue
		}

		var err error
		tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: uint64(r), Hash: roots[r]})
		require.NoError(t, err, "NewWithRoot")

		for pr := 0; pr <= r; pr++ {
			for p := 0; p < numPairsPerRound; p++ {
				key := []byte(fmt.Sprintf("key %d/%d", pr, p))
				value, err := tree.Get(ctx, key)
				require.NoError(t, err, "Get(%d, %s)", r, key)
				require.EqualValues(t, value, fmt.Sprintf("value %d/%d", pr, p))
			}
		}
	}

	// We must have pruned some.
	require.True(t, totalPruned > 0, "pruning must have pruned something")
}

// countCreatedNodes counts the number of nodes that have been created in the same
// round as the root is in and have not been previously seen.
func countCreatedNodes(t *testing.T, ndb db.NodeDB, root node.Root, seenNodes map[hash.Hash]bool) (nodes int) {
	err := db.Visit(context.Background(), ndb, root, func(ctx context.Context, n node.Node) bool {
		if n.GetCreatedRound() == root.Round && !seenNodes[n.GetHash()] {
			seenNodes[n.GetHash()] = true
			nodes++
		}
		return true
	})
	require.NoError(t, err, "Visit")
	return
}

func testPruneForkedRoots(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()

	// Create a root in round 0.
	tree := New(nil, ndb)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("moo"), []byte("goo"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	// Finalize round 0.
	err = ndb.Finalize(ctx, testNs, 0, []hash.Hash{rootHashR0_1})
	require.NoError(t, err, "Finalize")

	// Create a derived root A in round 1.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHashR0_1})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("dr"), []byte("A"))
	require.NoError(t, err, "Insert")
	err = tree.Remove(ctx, []byte("moo"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Create a derived root B in round 1.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHashR0_1})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("dr"), []byte("B"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Finalize round 1. Only derived root B was finalized, so derived root A
	// should be discarded.
	err = ndb.Finalize(ctx, testNs, 1, []hash.Hash{rootHashR1_2})
	require.NoError(t, err, "Finalize")

	// Create a derived root C from derived root B in round 2.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_2})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("yet"), []byte("another"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_1, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")
	// Finalize round 2.
	err = ndb.Finalize(ctx, testNs, 2, []hash.Hash{rootHashR2_1})
	require.NoError(t, err, "Finalize")

	// Prune round 1.
	_, err = ndb.Prune(ctx, testNs, 1)
	require.NoError(t, err, "Prune")

	// Prune round 0.
	_, err = ndb.Prune(ctx, testNs, 0)
	require.NoError(t, err, "Prune")

	// Make sure all the keys are there.
	for _, root := range []struct {
		Round uint64
		Hash  hash.Hash
		Keys  []string
	}{
		{2, rootHashR2_1, []string{"foo", "moo", "dr", "yet"}},
	} {
		tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: root.Round, Hash: root.Hash})
		require.NoError(t, err, "NewWithRoot")
		for _, key := range root.Keys {
			value, err := tree.Get(ctx, []byte(key))
			require.NoError(t, err, "Get(%d, %s)", root.Round, key)
			require.NotNil(t, value, "value should exist (%d, %s)", root.Round, key)
		}
	}
}

func testPruneLoneRootsShared(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()

	// Create a lone root (e.g., not included among the finalized roots)
	// that shares some nodes with a root that is among the finalized
	// roots. Make sure that the shared nodes aren't pruned.

	tree := New(nil, ndb)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 2"), []byte("bar2"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 3"), []byte("bar3"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 2"), []byte("bar2"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 3"), []byte("bar3"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("__extra__"), []byte("extra"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	err = ndb.Finalize(ctx, testNs, 0, []hash.Hash{rootHash1})
	require.NoError(t, err, "Finalize")

	// Check that the shared nodes are still there.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHash1})
	require.NoError(t, err, "NewWithRoot")
	value, err := tree.Get(ctx, []byte("foo"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("bar"), value)
	value, err = tree.Get(ctx, []byte("foo 2"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("bar2"), value)
	value, err = tree.Get(ctx, []byte("foo 3"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("bar3"), value)
}

func testPruneLoneRoots(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()

	// Create a root in round 0.
	tree := New(nil, ndb)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("moo"), []byte("goo"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Create another root in round 0.
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("goo"), []byte("blah"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_2, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Create yet another root in round 0.
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("yet"), []byte("another"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_3, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Create yet another root in round 0.
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("yet2"), []byte("another2"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_4, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Finalize round 0.
	err = ndb.Finalize(ctx, testNs, 0, []hash.Hash{rootHashR0_1, rootHashR0_2, rootHashR0_3, rootHashR0_4})
	require.NoError(t, err, "Finalize")

	// Create a distinct root in round 1.
	seenNodes := make(map[hash.Hash]bool)
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("different"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_1, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	nodesR1_1 := countCreatedNodes(t, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_1}, seenNodes)
	require.EqualValues(t, 1, nodesR1_1)

	// Create a derived root in round 1.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHashR0_2})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("different2"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Create two linked roots inside round 1 which will not be referenced
	// in subsequent rounds and so should be garbage collected.
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("first"), []byte("am i"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_3, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	nodesR1_3 := countCreatedNodes(t, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_3}, seenNodes)
	require.EqualValues(t, 1, nodesR1_3)

	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_3})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("second"), []byte("i am"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_4, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	nodesR1_4 := countCreatedNodes(t, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_4}, seenNodes)
	require.EqualValues(t, 2, nodesR1_4)

	// Create three linked roots inside round 1 where the first root is
	// derived from a root in round 0, the second root is derived from
	// the first root and the third root is derived from the second root
	// (both in the same round). All three should be garbage collected
	// as they are not referenced in subsequent rounds.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHashR0_3})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("first"), []byte("am i"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_5, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	nodesR1_5 := countCreatedNodes(t, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_5}, seenNodes)
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_5})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("second"), []byte("i am"))
	require.NoError(t, err, "Insert")
	err = tree.Remove(ctx, []byte("yet"))
	require.NoError(t, err, "Remove")
	_, rootHashR1_6, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	nodesR1_6 := countCreatedNodes(t, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_6}, seenNodes)
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_6})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("third"), []byte("i am not"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_7, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	nodesR1_7 := countCreatedNodes(t, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_7}, seenNodes)

	// Create three linked roots inside round 1 where the first root is
	// derived from a root in round 0, the second root is derived from
	// the first root and the third root is derived from the second root
	// (both in the same round). The third root is then referenced in round
	// 2 so only intermediate nodes should be garbage collected.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHashR0_4})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("first2"), []byte("am i"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_8, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_8})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("second2"), []byte("i am"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_9, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_9})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("third2"), []byte("i am not"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_10, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	// After these commits, 3 nodes are only referenced in intermediate roots
	// and should be garbage collected.

	// Finalize round 1.
	err = ndb.Finalize(ctx, testNs, 1, []hash.Hash{rootHashR1_1, rootHashR1_2, rootHashR1_4, rootHashR1_7, rootHashR1_10})
	require.NoError(t, err, "Finalize")

	// Create a distinct root in round 2.
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("blah"), []byte("brah"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_1, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")

	// Create a derived root in round 2.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_2})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("foo"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_2, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")

	// Create another derived root in round 2.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 1, Hash: rootHashR1_10})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("foo2"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_3, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")

	// Finalize round 2.
	err = ndb.Finalize(ctx, testNs, 2, []hash.Hash{rootHashR2_1, rootHashR2_2, rootHashR2_3})
	require.NoError(t, err, "Finalize")

	// Prune round 1, all of the lone root's node should have been removed.
	pruned, err := ndb.Prune(ctx, testNs, 1)
	require.NoError(t, err, "Prune")
	// Lone roots have nodesR1_1+nodesR1_3+nodesR1_4+nodesR1_5+nodesR1_6+nodesR1_7 nodes,
	// intermediate lone roots have 3 nodes and derived roots have 2 nodes.
	require.EqualValues(t, 2+nodesR1_1+nodesR1_3+nodesR1_4+nodesR1_5+nodesR1_6+nodesR1_7+3, pruned)

	// Check that roots in round 0 and 2 are still there.
	for _, root := range []struct {
		Round uint64
		Hash  hash.Hash
		Keys  []string
	}{
		{0, rootHashR0_1, []string{"foo", "moo"}},
		{0, rootHashR0_2, []string{"goo"}},
		{0, rootHashR0_3, []string{"yet"}},
		{0, rootHashR0_4, []string{"yet2"}},
		{2, rootHashR2_1, []string{"blah"}},
		{2, rootHashR2_2, []string{"goo", "different2", "foo"}},
		{2, rootHashR2_3, []string{"yet2", "first2", "second2", "third2", "foo2"}},
	} {
		tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: root.Round, Hash: root.Hash})
		require.NoError(t, err, "NewWithRoot")
		for _, key := range root.Keys {
			value, err := tree.Get(ctx, []byte(key))
			require.NoError(t, err, "Get(%d, %s)", root.Round, key)
			require.NotNil(t, value, "value should exist (%d, %s)", root.Round, key)
		}
	}
}

func testErrors(t *testing.T, ndb db.NodeDB) {
	ctx := context.Background()

	// Commit root for round 0.
	tree := New(nil, ndb)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Commit root for round 1.
	tree = New(nil, ndb)
	err = tree.Insert(ctx, []byte("another"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_1, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Commit for non-following round should fail.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: rootHashR1_1})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("moo"), []byte("moo"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 100)
	require.Error(t, err, "Commit should fail for non-following round")
	require.Equal(t, db.ErrRootMustFollowOld, err)

	// Commit with mismatched old root should fail.
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 99, Hash: rootHashR1_1})
	require.NoError(t, err, "NewWithRoot")
	err = tree.Insert(ctx, []byte("moo"), []byte("moo"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 100)
	require.Error(t, err, "Commit should fail for mismatched round")
	require.Equal(t, db.ErrPreviousRoundMismatch, err)

	// Commit with non-existent old root should fail.
	var bogusRoot hash.Hash
	bogusRoot.FromBytes([]byte("bogus root"))
	tree, err = NewWithRoot(ctx, nil, ndb, node.Root{Namespace: testNs, Round: 0, Hash: bogusRoot})
	require.NoError(t, err, "NewWithRoot")
	_, _, err = tree.Commit(ctx, testNs, 1)
	require.Error(t, err, "Commit should fail for invalid root")
	require.Equal(t, db.ErrRootNotFound, err)

	// Finalize of round 1 should fail as round 0 is not finalized.
	err = ndb.Finalize(ctx, testNs, 1, []hash.Hash{rootHashR1_1})
	require.Error(t, err, "Finalize should fail as previous round not finalized")
	require.Equal(t, db.ErrNotFinalized, err)

	// Finalizing a round twice should fail.
	err = ndb.Finalize(ctx, testNs, 0, []hash.Hash{rootHashR0_1})
	require.NoError(t, err, "Finalize")
	err = ndb.Finalize(ctx, testNs, 0, []hash.Hash{rootHashR0_1})
	require.Error(t, err, "Finalize should fail as round is already finalized")
	require.Equal(t, db.ErrAlreadyFinalized, err)
}

func testBackend(
	t *testing.T,
	initBackend func(t *testing.T) (db.NodeDB, interface{}),
	finiBackend func(t *testing.T, ndb db.NodeDB, custom interface{}),
	skipTests []string,
) {
	tests := []struct {
		name string
		fn   func(*testing.T, db.NodeDB)
	}{
		{"Basic", testBasic},
		{"LongKeys", testLongKeys},
		{"EmptyKeys", testEmptyKeys},
		{"InsertCommitBatch", testInsertCommitBatch},
		{"InsertCommitEach", testInsertCommitEach},
		{"Remove", testRemove},
		{"Visit", testVisit},
		{"ApplyWriteLog", testApplyWriteLog},
		{"SyncerBasic", testSyncerBasic},
		{"SyncerGetPath", testSyncerGetPath},
		{"SyncerRootEmptyLabelNeedsDeref", testSyncerRootEmptyLabelNeedsDeref},
		{"SyncerRemove", testSyncerRemove},
		{"SyncerInsert", testSyncerInsert},
		{"SyncerNilNodes", testSyncerNilNodes},
		{"ValueEviction", testValueEviction},
		{"NodeEviction", testNodeEviction},
		{"DoubleInsertWithEviction", testDoubleInsertWithEviction},
		{"DebugDump", testDebugDump},
		{"DebugStats", testDebugStats},
		{"OnCommitHooks", testOnCommitHooks},
		{"HasRoot", testHasRoot},
		{"PruneBasic", testPruneBasic},
		{"PruneManyRounds", testPruneManyRounds},
		{"PruneLoneRoots", testPruneLoneRoots},
		{"PruneLoneRootsShared", testPruneLoneRootsShared},
		{"PruneForkedRoots", testPruneForkedRoots},
		{"PruneCheckpoints", testPruneCheckpoints},
		{"Errors", testErrors},
	}

	skipMap := make(map[string]bool, len(skipTests))
	for _, name := range skipTests {
		skipMap[name] = true
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if skipMap[tc.name] {
				t.Skip("skipping test for this backend")
			}

			backend, custom := initBackend(t)
			defer finiBackend(t, backend, custom)
			tc.fn(t, backend)
		})
	}
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
		}, nil)
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
		}, nil)
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
		},
		// LRU backend doesn't support everything, skip some tests.
		[]string{
			"PruneBasic",
			"PruneManyRounds",
			"PruneLoneRoots",
			"PruneLoneRootsShared",
			"PruneForkedRoots",
			"PruneCheckpoints",
			"Errors",
			"HasRoot",
		},
	)
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
		dir, err := ioutil.TempDir("", "mkvs.bench.leveldb")
		require.NoError(b, err, "TempDir")
		defer os.RemoveAll(dir)
		ndb, err := levelDb.New(dir)
		require.NoError(b, err, "New")
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
