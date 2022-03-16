package mkvs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	badgerDb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	mkvsTests "github.com/oasisprotocol/oasis-core/go/storage/mkvs/tests"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	insertItems  = 1000
	allItemsRoot = "2187c55627819b60069888ba86f83dc2a9f50c827624b0e31e31261806300ede"

	insertItemsShort  = 500
	allItemsRootShort = "cf6e9b6a26e10a8218b8658ac9302af1a4c1ae4e1b1a7633860a0f81fb759495"

	longKey          = "Unlock the potential of your data without compromising security or privacy"
	longValue        = "The platform that puts data privacy first. From sharing medical records, to analyzing personal financial information, to training machine learning models, the Oasis platform supports applications that use even the most sensitive data without compromising privacy or performance."
	allLongItemsRoot = "d829bb244a709bacf33bc2d8b4a016592e5310a10910aa980ef91cb3b4347dcb"
)

var (
	testNs = common.NewTestNamespaceFromSeed([]byte("oasis mkvs test ns"), 0)

	_ syncer.ReadSyncer = (*dummySerialSyncer)(nil)
)

// NodeDBFactory is a function that creates a new node database for the given namespace.
type NodeDBFactory func(ns common.Namespace) (db.NodeDB, error)

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

func foldWriteLogIterator(t *testing.T, w writelog.Iterator) writelog.WriteLog {
	writeLog := writelog.WriteLog{}

	for {
		more, err := w.Next()
		require.NoError(t, err, "error iterating over WriteLogIterator")
		if !more {
			break
		}

		val, err := w.Value()
		require.NoError(t, err, "error iterating over WriteLogIterator")
		writeLog = append(writeLog, val)
	}
	return writeLog
}

func (s *dummySerialSyncer) SyncGet(ctx context.Context, request *syncer.GetRequest) (*syncer.ProofResponse, error) {
	raw := cbor.Marshal(request)
	var rq syncer.GetRequest
	if err := cbor.Unmarshal(raw, &rq); err != nil {
		return nil, err
	}
	rsp, err := s.backing.SyncGet(ctx, &rq)
	if err != nil {
		return nil, err
	}
	raw = cbor.Marshal(rsp)
	var rs syncer.ProofResponse
	if err := cbor.Unmarshal(raw, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *dummySerialSyncer) SyncGetPrefixes(ctx context.Context, request *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	raw := cbor.Marshal(request)
	var rq syncer.GetPrefixesRequest
	if err := cbor.Unmarshal(raw, &rq); err != nil {
		return nil, err
	}
	rsp, err := s.backing.SyncGetPrefixes(ctx, &rq)
	if err != nil {
		return nil, err
	}
	raw = cbor.Marshal(rsp)
	var rs syncer.ProofResponse
	if err := cbor.Unmarshal(raw, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (s *dummySerialSyncer) SyncIterate(ctx context.Context, request *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	raw := cbor.Marshal(request)
	var rq syncer.IterateRequest
	if err := cbor.Unmarshal(raw, &rq); err != nil {
		return nil, err
	}
	rsp, err := s.backing.SyncIterate(ctx, &rq)
	if err != nil {
		return nil, err
	}
	raw = cbor.Marshal(rsp)
	var rs syncer.ProofResponse
	if err := cbor.Unmarshal(raw, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func testBasic(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

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
	require.Equal(t, "db67c0572006673b488342a45e6590a75e8919265e6da706c80c6b2776017aa7", root.String())
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
	require.Equal(t, "e627581db43e18410a52793e662e4f21ae6a4fca14e16915a85ec4c3e3e41a13", root.String())
	require.Equal(t, writeLogToMap(writelog.WriteLog{writelog.LogEntry{Key: keyOne, Value: valueOne}, writelog.LogEntry{Key: keyZero, Value: valueZero}}), writeLogToMap(log))
	require.Equal(t, writelog.LogInsert, log[0].Type())
	require.Equal(t, writelog.LogInsert, log[1].Type())

	// Create a new tree backed by the same database.
	tree = NewWithRoot(nil, ndb, node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      root,
	})

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
	require.Equal(t, "db67c0572006673b488342a45e6590a75e8919265e6da706c80c6b2776017aa7", root.String())
	require.Equal(t, writeLogToMap(writelog.WriteLog{writelog.LogEntry{Key: keyOne, Value: nil}}), writeLogToMap(log))
	require.Equal(t, writelog.LogDelete, log[0].Type())

	_, err = tree.CommitKnown(ctx, node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      root,
	})
	require.NoError(t, err, "CommitKnown")

	bogusRoot := hash.NewFromBytes([]byte("bogus root"))
	_, err = tree.CommitKnown(ctx, node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
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

func testLongKeys(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState, Capacity(0, 512))

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

func testEmptyKeys(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	testEmptyKeyInsert := func(t *testing.T, ctx context.Context, tree Tree) {
		emptyKey := node.Key("")
		emptyValue := []byte("empty value")

		err := tree.Insert(ctx, emptyKey, emptyValue)
		require.NoError(t, err, "Insert")

		value, err := tree.Get(ctx, emptyKey)
		require.NoError(t, err, "Get")
		require.Equal(t, emptyValue, value, "empty value after insert")
	}

	testEmptyKeyRemove := func(t *testing.T, ctx context.Context, tree Tree) {
		emptyKey := node.Key("")

		err := tree.Remove(ctx, emptyKey)
		require.NoError(t, err, "Remove")

		value, err := tree.Get(ctx, emptyKey)
		require.NoError(t, err, "Get")
		require.Equal(t, []byte(nil), value, "empty value after remove")
	}

	testZerothDiscriminatorBitInsert := func(t *testing.T, ctx context.Context, tree Tree) {
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

	testZerothDiscriminatorBitRemove := func(t *testing.T, ctx context.Context, tree Tree) {
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

func testInsertCommitBatch(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

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

func testInsertCommitEach(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

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

func testRemove(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	// First insert keys 0..n and remove them in order n..0.
	var roots []hash.Hash
	keys, values := generateKeyValuePairsEx("", insertItemsShort)
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

	require.Equal(t, allItemsRootShort, roots[len(roots)-1].String())

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

func testSyncerBasic(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	keys, values, r, tree := generatePopulatedTree(t, ndb)

	// Create a "remote" tree that talks to the original tree via the
	// syncer interface.

	stats := syncer.NewStatsCollector(tree)
	remoteTree := NewWithRoot(stats, nil, r, Capacity(0, 0))

	for i := 0; i < len(keys); i++ {
		value, err := remoteTree.Get(ctx, keys[i])
		require.NoError(t, err, "Get")
		require.Equal(t, values[i], value)
	}

	require.Equal(t, len(keys), stats.SyncGetCount, "SyncGet count")
	require.Equal(t, 0, stats.SyncGetPrefixesCount, "SyncGetPrefixes count")
	require.Equal(t, 0, stats.SyncIterateCount, "SyncIterate count")
}

func testSyncerRootEmptyLabelNeedsDeref(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

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
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}

	testGet := func(t *testing.T, tree Tree) {
		value, err := tree.Get(ctx, []byte{0xFF})
		require.NoError(t, err, "Get")
		require.EqualValues(t, value, []byte("foo"))

		value, err = tree.Get(ctx, []byte{0x00})
		require.NoError(t, err, "Get")
		require.EqualValues(t, value, []byte("bar"))
	}
	testRemove := func(t *testing.T, tree Tree) {
		err := tree.Remove(ctx, []byte{0xFF})
		require.NoError(t, err, "Remove")
		err = tree.Remove(ctx, []byte{0x00})
		require.NoError(t, err, "Remove")
	}
	testInsert := func(t *testing.T, tree Tree) {
		err := tree.Insert(ctx, []byte{0xFF, 0xFF}, []byte("foo"))
		require.NoError(t, err, "Insert")
		err = tree.Insert(ctx, []byte{0x00, 0x00}, []byte("bar"))
		require.NoError(t, err, "Insert")
	}

	// Create a remote tree so we will need to deref.

	t.Run("Get", func(t *testing.T) {
		remoteTree := NewWithRoot(tree, nil, root)
		testGet(t, remoteTree)
	})

	t.Run("Remove", func(t *testing.T) {
		remoteTree := NewWithRoot(tree, nil, root)
		testRemove(t, remoteTree)
	})

	t.Run("Insert", func(t *testing.T) {
		remoteTree := NewWithRoot(tree, nil, root)
		testInsert(t, remoteTree)
	})
}

func testSyncerRemove(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

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
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      roots[len(roots)-1],
	}
	stats := syncer.NewStatsCollector(tree)
	remoteTree := NewWithRoot(stats, nil, root)

	for i := len(keys) - 1; i >= 0; i-- {
		err := remoteTree.Remove(ctx, keys[i])
		require.NoError(t, err, "Remove")
	}

	_, rootHash, err := remoteTree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, rootHash.IsEmpty())

	require.Equal(t, 850, stats.SyncGetCount, "SyncGet count")
	require.Equal(t, 0, stats.SyncGetPrefixesCount, "SyncGetPrefixes count")
	require.Equal(t, 0, stats.SyncIterateCount, "SyncIterate count")
}

func testSyncerInsert(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}
	stats := syncer.NewStatsCollector(tree)
	remoteTree := NewWithRoot(stats, nil, root)

	keys, values = generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err = remoteTree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	require.Equal(t, 1000, stats.SyncGetCount, "SyncGet count")
	require.Equal(t, 0, stats.SyncGetPrefixesCount, "SyncGetPrefixes count")
	require.Equal(t, 0, stats.SyncIterateCount, "SyncIterate count")
}

func testSyncerNilNodes(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	var err error

	ctx := context.Background()
	tree := New(nil, nil, node.RootTypeState)

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
	remote := NewWithRoot(wire, nil, node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      root,
	})

	// Now try inserting a k-v pair that will force the tree to traverse through the nil node
	// and dereference it.
	err = remote.Insert(ctx, []byte("insert"), []byte("key"))
	require.NoError(t, err, "Insert")
}

func testSyncerPrefetchPrefixes(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	keys, values, root, tree := generatePopulatedTree(t, ndb)

	stats := syncer.NewStatsCollector(tree)
	remoteTree := NewWithRoot(stats, nil, root, Capacity(0, 0))

	// Prefetch keys starting with prefix "key".
	err := remoteTree.PrefetchPrefixes(ctx, [][]byte{[]byte("key")}, 1000)
	require.NoError(t, err, "PrefetchPrefixes")
	require.EqualValues(t, 1, stats.SyncGetPrefixesCount, "SyncGetPrefixes should be called exactly once")

	// Ensure that everything is now cached.
	for i, key := range keys {
		v, err := remoteTree.Get(ctx, key)
		require.NoError(t, err, "Get")
		require.EqualValues(t, values[i], v)
	}
	require.EqualValues(t, 0, stats.SyncGetCount, "SyncGet should not be called")
	require.EqualValues(t, 1, stats.SyncGetPrefixesCount, "SyncGetPrefixes should not be called anymore")
	require.EqualValues(t, 0, stats.SyncIterateCount, "SyncIterate should not be called")
}

func testValueEviction(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState, Capacity(0, 512)).(*tree)

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, _, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	require.EqualValues(t, 999, tree.cache.internalNodeCount, "Cache.InternalNodeCount")
	// Only a subset of the leaf values should remain in cache.
	require.EqualValues(t, 416, tree.cache.valueSize, "Cache.ValueSize")
}

func testNodeEviction(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState, Capacity(128, 0)).(*tree)

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

	// Only a subset of nodes should remain in cache.
	require.EqualValues(t, 128, tree.cache.internalNodeCount, "Cache.InternalNodeCount")
	require.EqualValues(t, 14912, tree.cache.valueSize, "Cache.LeafValueSize")
}

func testDoubleInsertWithEviction(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState, Capacity(128, 0))

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

func testDebugDumpLocal(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	err := tree.Insert(ctx, []byte("foo 1"), []byte("bar 1"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 2"), []byte("bar 2"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 3"), []byte("bar 3"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")

	buffer := &bytes.Buffer{}
	tree.DumpLocal(ctx, buffer, 0)
	require.True(t, len(buffer.Bytes()) > 0)
}

func testApplyWriteLog(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	keys, values := generateKeyValuePairsEx("", 100)

	// Insert some items first.
	var writeLog writelog.WriteLog
	for i := range keys {
		writeLog = append(writeLog, writelog.LogEntry{Key: keys[i], Value: values[i]})
	}

	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
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

	err = tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(writeLog))
	require.NoError(t, err, "ApplyWriteLog")
	var rootHash hash.Hash
	_, rootHash, err = tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.True(t, rootHash.IsEmpty(), "root hash must be empty after removal of all items")
}

func testOnCommitHooks(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	var emptyRoot hash.Hash
	emptyRoot.Empty()
	root := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      emptyRoot,
	}

	batch, err := ndb.NewBatch(root, root.Version, false)
	require.NoError(t, err, "NewBatch")
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

	err = batch.Commit(root)
	require.NoError(t, err, "Commit")
	require.EqualValues(t, calls, []int{1, 2, 3}, "OnCommit hooks should fire in order")
}

func testCommitNoPersist(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	err := tree.Insert(ctx, []byte("this key"), []byte("should not be persisted"))
	require.NoError(t, err, "Insert")

	log, root, err := tree.Commit(ctx, testNs, 0, NoPersist())
	require.NoError(t, err, "Commit")
	require.Equal(t, "46141a682ada455db80763c17c4e76535adaafaa2508d4fdae8a5ee5c0166629", root.String(), "computed root should be correct")
	require.Len(t, log, 1, "write log should contain one item")

	// Make sure we can still commit and finalize something at an arbitrary higher round.

	err = tree.Insert(ctx, []byte("but now"), []byte("we will persist everything"))
	require.NoError(t, err, "Insert")

	log, root, err = tree.Commit(ctx, testNs, 42)
	require.NoError(t, err, "Commit")
	require.Equal(t, "d9b2effdff5a22145cef58c7c84c8040ee441e65a30e75d13e7490939299a4f4", root.String(), "computed root should be correct")
	require.Len(t, log, 2, "write log should contain two items")

	nodeRoot := node.Root{
		Namespace: testNs,
		Version:   42,
		Type:      node.RootTypeState,
		Hash:      root,
	}
	err = ndb.Finalize(ctx, []node.Root{nodeRoot})
	require.NoError(t, err, "Finalize")

	roots, err := ndb.GetRootsForVersion(ctx, 42)
	require.NoError(t, err, "GetRootsForVersion")
	require.Len(t, roots, 1, "there should only be one root")
	require.Equal(t, nodeRoot, roots[0], "the root hash should be correct")

	// Make sure everything has been persisted now.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 42, Type: node.RootTypeState, Hash: root})

	value, err := tree.Get(ctx, []byte("this key"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("should not be persisted"), value)

	value, err = tree.Get(ctx, []byte("but now"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("we will persist everything"), value)
}

func testHasRoot(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	// Test that an empty root is always implicitly present.
	root := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
	}
	root.Hash.Empty()
	require.True(t, ndb.HasRoot(root), "HasRoot should return true on empty root")

	// Create a root in version 0.
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root = node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash1,
	}

	// Finalize version 0.
	err = ndb.Finalize(ctx, []node.Root{root})
	require.NoError(t, err, "Finalize")

	// Make sure that HasRoot returns true.
	require.True(t, ndb.HasRoot(root), "HasRoot should return true for existing root")
	root.Hash.FromBytes([]byte("invalid root"))
	require.False(t, ndb.HasRoot(root), "HasRoot should return false for non-existing root")

	// Create a different root in version 1.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("goo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	// Finalize version 1.
	root2 := node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash2,
	}
	err = ndb.Finalize(ctx, []node.Root{root2})
	require.NoError(t, err, "Finalize")

	// Make sure that HasRoot for root hash from version 0 but with
	// version 1 passed returns false.
	root = node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash1,
	}
	require.False(t, ndb.HasRoot(root), "HasRoot should return false for non-existing root")
	root.Hash = rootHash2
	require.True(t, ndb.HasRoot(root), "HasRoot should return true for existing root")
}

func testGetRootsForVersion(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	// Create two roots in version 10.
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 10)
	require.NoError(t, err, "Commit")

	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("bar"), []byte("foo"))
	require.NoError(t, err, "Insert")
	_, rootHash2, err := tree.Commit(ctx, testNs, 10)
	require.NoError(t, err, "Commit")

	// Finalize version 10.
	root1 := node.Root{
		Namespace: testNs,
		Version:   10,
		Type:      node.RootTypeState,
		Hash:      rootHash1,
	}
	root2 := node.Root{
		Namespace: testNs,
		Version:   10,
		Type:      node.RootTypeState,
		Hash:      rootHash2,
	}
	err = ndb.Finalize(ctx, []node.Root{root1, root2})
	require.NoError(t, err, "Finalize")

	roots, err := ndb.GetRootsForVersion(ctx, 10)
	require.NoError(t, err, "GetRootsForVersion")
	require.Len(t, roots, 2, "GetRootsForVersion should return the correct number of roots")
	require.Contains(t, roots, root1, "GetRootsForVersion should return the correct roots")
	require.Contains(t, roots, root2, "GetRootsForVersion should return the correct roots")

	roots, err = ndb.GetRootsForVersion(ctx, 1)
	require.NoError(t, err, "GetRootsForVersion")
	require.Len(t, roots, 0, "GetRootsForVersion should return no roots for eaerlier versions")

	roots, err = ndb.GetRootsForVersion(ctx, 11)
	require.NoError(t, err, "GetRootsForVersion")
	require.Len(t, roots, 0, "GetRootsForVersion should return no roots for later versions")
}

func testSize(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	size, err := ndb.Size()
	require.NoError(t, err, "Size")

	// Put something in the database.
	tree := New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	root1 := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash1,
	}
	err = ndb.Finalize(ctx, []node.Root{root1})
	require.NoError(t, err, "Finalize")

	// Reopen database to force flush.
	ndb.Close()
	ndb, err = factory(testNs)
	require.NoError(t, err, "ndb.New")
	defer ndb.Close()

	// Make sure size reports something that makes sense.
	newSize, err := ndb.Size()
	require.NoError(t, err, "Size")
	require.True(t, newSize > size, "Size should be greater than before")
}

func testMergeWriteLog(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	keyZero := []byte("foo")
	valueZero := []byte("bar")
	keyOne := []byte("baz")
	valueOne := []byte("quux")

	emptyRoot := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
	}
	emptyRoot.Hash.Empty()

	// Put some stuff in the tree.
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, keyZero, valueZero)
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root1 := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash1,
	}

	wli, err := ndb.GetWriteLog(ctx, emptyRoot, root1)
	require.NoError(t, err, "GetWriteLog")

	wl := writeLogToMap(foldWriteLogIterator(t, wli))
	require.Equal(t, writeLogToMap(writelog.WriteLog{writelog.LogEntry{Key: keyZero, Value: valueZero}}), wl)

	// Continue adding to this same tree.
	err = tree.Insert(ctx, keyOne, valueOne)
	require.NoError(t, err, "Insert")
	_, rootHash2, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root2 := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash2,
	}

	// Check that we can get a combined write log from the first root to the third one.
	wli, err = ndb.GetWriteLog(ctx, emptyRoot, root2)
	require.NoError(t, err, "GetWriteLog")

	wlDb := writeLogToMap(foldWriteLogIterator(t, wli))
	wlLiteral := writeLogToMap(writelog.WriteLog{
		writelog.LogEntry{Key: keyZero, Value: valueZero},
		writelog.LogEntry{Key: keyOne, Value: valueOne},
	})
	require.Equal(t, wlLiteral, wlDb)

	// We can still get write logs to intermediate roots.
	wli, err = ndb.GetWriteLog(ctx, emptyRoot, root1)
	require.NoError(t, err, "GetWriteLog")
	_ = writelog.DrainIterator(wli)
	wli, err = ndb.GetWriteLog(ctx, root1, root2)
	require.NoError(t, err, "GetWriteLog")
	_ = writelog.DrainIterator(wli)

	// Make sure that we fail with more than two hops.
	err = tree.Insert(ctx, []byte("moo"), []byte("goo"))
	require.NoError(t, err, "Insert")
	_, rootHash3, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	root3 := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash3,
	}

	_, err = ndb.GetWriteLog(ctx, emptyRoot, root3)
	require.Error(t, err, "GetWriteLog")
	wli, err = ndb.GetWriteLog(ctx, root2, root3)
	require.NoError(t, err, "GetWriteLog")
	_ = writelog.DrainIterator(wli)
}

func testPruneBasic(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	// Create some keys in version 0.
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("moo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	// Test that we cannot prune non-finalized versions.
	err = ndb.Prune(ctx, 0)
	require.Error(t, err, "Prune should fail for non-finalized versions")
	require.Equal(t, db.ErrNotFinalized, err)
	// Finalize version 0.
	root1 := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash1,
	}
	err = ndb.Finalize(ctx, []node.Root{root1})
	require.NoError(t, err, "Finalize")

	// Remove key in version 1.
	err = tree.Remove(ctx, []byte("foo"))
	require.NoError(t, err, "Remove")
	err = tree.Insert(ctx, []byte("another"), []byte("value"))
	require.NoError(t, err, "Insert")
	_, rootHash2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	// Test that we cannot prune non-finalized versions.
	err = ndb.Prune(ctx, 1)
	require.Error(t, err, "Prune should fail for non-finalized versions")
	require.Equal(t, db.ErrNotFinalized, err)
	// Finalize version 1.
	root2 := node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash2,
	}
	err = ndb.Finalize(ctx, []node.Root{root2})
	require.NoError(t, err, "Finalize")

	// Add some keys in version 2.
	err = tree.Insert(ctx, []byte("blah"), []byte("ugh"))
	require.NoError(t, err, "Insert")
	_, rootHash3, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")
	// Test that we cannot prune non-finalized versions.
	err = ndb.Prune(ctx, 2)
	require.Error(t, err, "Prune should fail for non-finalized versions")
	require.Equal(t, db.ErrNotFinalized, err)
	// Finalize version 2.
	root3 := node.Root{
		Namespace: testNs,
		Version:   2,
		Type:      node.RootTypeState,
		Hash:      rootHash3,
	}
	err = ndb.Finalize(ctx, []node.Root{root3})
	require.NoError(t, err, "Finalize")

	earliestVersion := ndb.GetEarliestVersion()
	require.EqualValues(t, 0, earliestVersion, "earliest version should be correct")
	latestVersion, exists := ndb.GetLatestVersion()
	require.EqualValues(t, 2, latestVersion, "latest version should be correct")
	require.True(t, exists, "latest version should exist")

	// Prune version 0.
	err = ndb.Prune(ctx, 0)
	require.NoError(t, err, "Prune")

	// Reopen database to force compaction.
	ndb.Close()
	ndb, err = factory(testNs)
	require.NoError(t, err, "ndb.New")
	defer ndb.Close()

	earliestVersion = ndb.GetEarliestVersion()
	require.EqualValues(t, 1, earliestVersion, "earliest version should be correct")
	latestVersion, exists = ndb.GetLatestVersion()
	require.EqualValues(t, 2, latestVersion, "latest version should be correct")
	require.True(t, exists, "latest version should exist")

	// Keys must still be available in version 2.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 2, Type: node.RootTypeState, Hash: rootHash3})
	value, err := tree.Get(ctx, []byte("blah"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("ugh"), value)
	value, err = tree.Get(ctx, []byte("moo"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("bar"), value)
	value, err = tree.Get(ctx, []byte("another"))
	require.NoError(t, err, "Get")
	require.EqualValues(t, []byte("value"), value)
	// Removed key must be gone.
	value, err = tree.Get(ctx, []byte("foo"))
	require.NoError(t, err, "Get")
	require.Nil(t, value, "removed key must be gone")

	// Version 0 must be gone.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHash1})
	_, err = tree.Get(ctx, []byte("foo"))
	require.Error(t, err, "Get")
}

func testPruneManyVersions(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	const numVersions = 50
	const numPairsPerVersion = 50

	for r := 0; r < numVersions; r++ {
		for p := 0; p < numPairsPerVersion; p++ {
			key := []byte(fmt.Sprintf("key %d/%d", r, p))
			value := []byte(fmt.Sprintf("value %d/%d", r, p))
			err := tree.Insert(ctx, key, value)
			require.NoError(t, err, "Insert")
		}

		_, rootHash, err := tree.Commit(ctx, testNs, uint64(r))
		require.NoError(t, err, "Commit")
		root := node.Root{
			Namespace: testNs,
			Version:   uint64(r),
			Type:      node.RootTypeState,
			Hash:      rootHash,
		}
		err = ndb.Finalize(ctx, []node.Root{root})
		require.NoError(t, err, "Finalize")
	}

	// Prune all versions except the last one.
	for r := 0; r < numVersions-1; r++ {
		err := ndb.Prune(ctx, uint64(r))
		require.NoError(t, err, "Prune")
	}

	// Reopen database to force compaction.
	ndb.Close()
	ndb, err := factory(testNs)
	require.NoError(t, err, "ndb.New")
	defer ndb.Close()

	// Check that the latest version has all the keys.
	for r := 0; r < numVersions; r++ {
		for p := 0; p < numPairsPerVersion; p++ {
			key := []byte(fmt.Sprintf("key %d/%d", r, p))
			value, err := tree.Get(ctx, key)
			require.NoError(t, err, "Get")
			require.EqualValues(t, value, fmt.Sprintf("value %d/%d", r, p))
		}
	}
}

func testPruneForkedRoots(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	// Create a root in version 0.
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("moo"), []byte("goo"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	// Finalize version 0.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_1}})
	require.NoError(t, err, "Finalize")

	// Create a derived root A in version 1.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_1})
	err = tree.Insert(ctx, []byte("dr"), []byte("A"))
	require.NoError(t, err, "Insert")
	err = tree.Remove(ctx, []byte("moo"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_1, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Create a derived root B in version 1.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_1})
	err = tree.Insert(ctx, []byte("dr"), []byte("B"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Finalize version 1. Only derived root B was finalized, so derived root A
	// should be discarded.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_2}})
	require.NoError(t, err, "Finalize")

	// Make sure that the write log for the discarded root is gone.
	rootR0_1 := node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_1}
	rootR1_1 := node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_1}
	rootR1_2 := node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_2}
	_, err = ndb.GetWriteLog(ctx, rootR0_1, rootR1_1)
	require.Error(t, err, "GetWriteLog")
	// Make sure that the write log for the non-discarded root exists.
	_, err = ndb.GetWriteLog(ctx, rootR0_1, rootR1_2)
	require.NoError(t, err, "GetWriteLog")

	// Create a derived root C from derived root B in version 2.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_2})
	err = tree.Insert(ctx, []byte("yet"), []byte("another"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_1, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")
	// Finalize version 2.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 2, Type: node.RootTypeState, Hash: rootHashR2_1}})
	require.NoError(t, err, "Finalize")

	// Prune version 1 (should fail as it is not the earliest version).
	err = ndb.Prune(ctx, 1)
	require.Error(t, err, "Prune")
	require.Equal(t, db.ErrNotEarliest, err)

	// Prune versions 0 and 1.
	err = ndb.Prune(ctx, 0)
	require.NoError(t, err, "Prune")
	err = ndb.Prune(ctx, 1)
	require.NoError(t, err, "Prune")

	// Reopen database to force compaction.
	ndb.Close()
	ndb, err = factory(testNs)
	require.NoError(t, err, "ndb.New")
	defer ndb.Close()

	// Make sure all the keys are there.
	for _, root := range []struct {
		Version uint64
		Hash    hash.Hash
		Keys    []string
	}{
		{2, rootHashR2_1, []string{"foo", "moo", "dr", "yet"}},
	} {
		tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: root.Version, Type: node.RootTypeState, Hash: root.Hash})

		for _, key := range root.Keys {
			value, err := tree.Get(ctx, []byte(key))
			require.NoError(t, err, "Get(%d, %s)", root.Version, key)
			require.NotNil(t, value, "value should exist (%d, %s)", root.Version, key)
		}
	}
}

func testPruneLoneRootsShared(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	// Create a lone root (e.g., not included among the finalized roots)
	// that shares some nodes with a root that is among the finalized
	// roots. Make sure that the shared nodes aren't pruned.

	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 2"), []byte("bar2"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("foo 3"), []byte("bar3"))
	require.NoError(t, err, "Insert")
	_, rootHash1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	tree = New(nil, ndb, node.RootTypeState)
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

	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHash1}})
	require.NoError(t, err, "Finalize")

	// Check that the shared nodes are still there.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHash1})
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

func testPruneLoneRootsShared2(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	type item struct {
		Key   string
		Value string
	}
	batches := []struct {
		Namespace common.Namespace
		Version   uint64
		SrcRoot   string
		DstRoot   string
		Finalized bool
		Items     []item
	}{
		{
			Namespace: testNs,
			Version:   4,
			SrcRoot:   "xnK40e9W7Sirh8NiLFEUBpvdOte4+XN0mNDAHs7wlno=",
			DstRoot:   "HDRPGZxGtdYTxcEwY8xMEQb5glc5rzc30q27u2CceVU=",
			Items: []item{
				{
					Key: "VFxlQ0wtW+UFzn4ojduOXMqLVlgtTzk5tN+eysKJiu7nAA==",
					Value: "glkBGqNkYXJnc6Jja2V5eEpVbmxvY2sgdGhlIHBvdGVudGlhbCBvZiB5b3VyIGRhdGEgd2l0aG91" +
						"dCBjb21wcm9taXNpbmcgc2VjdXJpdHkgb3IgcHJpdmFjeWV2YWx1ZXh5VGhlIHBsYXRmb3JtIHRo" +
						"YXQgcHV0cyBkYXRhIHByaXZhY3kgZmlyc3QuIEZyb20gc2hhcmluZyBtZWRpY2FsIHJlY29yZHMs" +
						"IHRvIGFuYWx5emluZyBwZXJzb25hbCBmaW5hbmNpYWwgaW5mb3JtYXRpb24gZXRjLmZtZXRob2Rm" +
						"aW5zZXJ0cHByZWRpY3RlZF9yd19zZXSjaHJlYWRfc2V0gGl3cml0ZV9zZXSAa2dyYW51bGFyaXR5" +
						"AAA=",
				},
			},
		},
		{
			Namespace: testNs,
			Version:   4,
			SrcRoot:   "HDRPGZxGtdYTxcEwY8xMEQb5glc5rzc30q27u2CceVU=",
			DstRoot:   "1mhju3gCBswUklbJuiifvVJDY6QeNiqRx2F1MDdxcys=",
			Finalized: true,
			Items: []item{
				{
					Key: "RWt2X2tleVxlQ0wtW+UFzn4ojduOXMqLVlgtTzk5tN+eysKJiu7n",
					Value: "VW5sb2NrIHRoZSBwb3RlbnRpYWwgb2YgeW91ciBkYXRhIHdpdGhvdXQgY29tcHJvbWlzaW5nIHNl" +
						"Y3VyaXR5IG9yIHByaXZhY3k=",
				},
				{
					Key:   "RWt2X29wXGVDTC1b5QXOfiiN245cyotWWC1POTm0357KwomK7uc=",
					Value: "aW5zZXJ0",
				},
				{
					Key:   "VFxlQ0wtW+UFzn4ojduOXMqLVlgtTzk5tN+eysKJiu7nAQ==",
					Value: "gUqhZ1N1Y2Nlc3P2",
				},
			},
		},
		{
			Namespace: testNs,
			Version:   4,
			SrcRoot:   "HDRPGZxGtdYTxcEwY8xMEQb5glc5rzc30q27u2CceVU=",
			DstRoot:   "+h6pzinXfRJY1tnL7jXoGcbUfG0lFCYTX1TaDngycso=",
			Items: []item{
				{
					Key: "RWt2X2tleVxlQ0wtW+UFzn4ojduOXMqLVlgtTzk5tN+eysKJiu7n",
					Value: "VW5sb2NrIHRoZSBwb3RlbnRpYWwgb2YgeW91ciBkYXRhIHdpdGhvdXQgY29tcHJvbWlzaW5nIHNl" +
						"Y3VyaXR5IG9yIHByaXZhY3k=",
				},
				{
					Key:   "RWt2X29wXGVDTC1b5QXOfiiN245cyotWWC1POTm0357KwomK7uc=",
					Value: "aW5zZXJ0",
				},
				{
					Key:   "VFxlQ0wtW+UFzn4ojduOXMqLVlgtTzk5tN+eysKJiu7nAQ==",
					Value: "gUqhZ1N1Y2Nlc3P2",
				},
				{
					Key:   "X19ib29tX18=",
					Value: "cG9vZg==",
				},
			},
		},
	}

	var finalizedRoots []node.Root
	for _, batch := range batches {
		srcRootHashRaw, err := base64.StdEncoding.DecodeString(batch.SrcRoot)
		require.NoError(t, err, "base64.DecodeString")
		var srcRootHash hash.Hash
		err = srcRootHash.UnmarshalBinary(srcRootHashRaw)
		require.NoError(t, err, "hash.UnmarshalBinary")

		tree := NewWithRoot(nil, ndb, node.Root{
			Namespace: batch.Namespace,
			Version:   batch.Version,
			Type:      node.RootTypeState,
			Hash:      srcRootHash,
		})
		defer tree.Close()

		for _, item := range batch.Items {
			var key, value []byte
			key, err = base64.StdEncoding.DecodeString(item.Key)
			require.NoError(t, err, "base64.DecodeString")
			value, err = base64.StdEncoding.DecodeString(item.Value)
			require.NoError(t, err, "base64.DecodeString")
			err = tree.Insert(ctx, key, value)
			require.NoError(t, err, "Insert")
		}

		_, rootHash, err := tree.Commit(ctx, batch.Namespace, batch.Version)
		require.NoError(t, err, "Commit")

		dstRootHashRaw, err := base64.StdEncoding.DecodeString(batch.DstRoot)
		require.NoError(t, err, "base64.DecodeString")
		var dstRootHash hash.Hash
		err = dstRootHash.UnmarshalBinary(dstRootHashRaw)
		require.NoError(t, err, "hash.UnmarshalBinary")
		require.EqualValues(t, dstRootHash, rootHash, "computed root hash must be as expected")

		if batch.Finalized {
			finalizedRoots = append(finalizedRoots, node.Root{
				Namespace: batches[0].Namespace,
				Version:   batches[0].Version,
				Type:      node.RootTypeState,
				Hash:      rootHash,
			})
		}
	}

	err := ndb.Finalize(ctx, finalizedRoots)
	require.NoError(t, err, "Finalize")

	tree := NewWithRoot(nil, ndb, finalizedRoots[0])
	defer tree.Close()

	it := tree.NewIterator(ctx)
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		// Just iterate over the whole tree. If the tree is not consistent
		// this iteration will throw an error that a node is missing.
	}
	require.NoError(t, it.Err(), "tree should still be consistent")
}

func testPruneLoneRootsShared3(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	require := require.New(t)
	ctx := context.Background()

	// Create a root in version 0.
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 0)
	require.NoError(err, "Commit")

	// Create another root in version 0.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("moo"), []byte("goo"))
	require.NoError(err, "Insert")
	_, rootHashR0_2, err := tree.Commit(ctx, testNs, 0)
	require.NoError(err, "Commit")

	// Create the same root as the first root in version 1.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(err, "Insert")
	_, rootHashR1_1, err := tree.Commit(ctx, testNs, 1)
	require.NoError(err, "Commit")

	// Finalize version 0 with the second root.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_2}})
	require.NoError(err, "Finalize")

	// Make sure that the first root in version 1 is still valid.
	tree = NewWithRoot(nil, ndb, node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHashR1_1,
	})
	value, err := tree.Get(ctx, []byte("foo"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("bar"), value)
}

func testPruneLoneRootsShared4(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	require := require.New(t)
	ctx := context.Background()

	// Create a root in version 0.
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(err, "Insert")
	_, rootHashR0_1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(err, "Commit")

	// Create the same root as the first root in version 1.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(err, "Insert")
	_, rootHashR1_1, err := tree.Commit(ctx, testNs, 1)
	require.NoError(err, "Commit")

	// Finalize version 0.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_1}})
	require.NoError(err, "Finalize")
	// Finalize version 1.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_1}})
	require.NoError(err, "Finalize")
	// Prune version 0.
	err = ndb.Prune(ctx, 0)
	require.NoError(err, "Prune")

	// Reopen database to force compaction.
	ndb.Close()
	ndb, err = factory(testNs)
	require.NoError(err, "ndb.New")
	defer ndb.Close()

	// Make sure that the first root in version 1 is still valid.
	tree = NewWithRoot(nil, ndb, node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHashR1_1,
	})
	value, err := tree.Get(ctx, []byte("foo"))
	require.NoError(err, "Get")
	require.EqualValues([]byte("bar"), value)
}

func testPruneLoneRoots(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	// Create a root in version 0.
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	err = tree.Insert(ctx, []byte("moo"), []byte("goo"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Create another root in version 0.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("goo"), []byte("blah"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_2, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Create yet another root in version 0.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("yet"), []byte("another"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_3, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Create yet another root in version 0.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("yet2"), []byte("another2"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_4, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Finalize version 0.
	var finalRoots []node.Root
	for _, hash := range []hash.Hash{rootHashR0_1, rootHashR0_2, rootHashR0_3, rootHashR0_4} {
		finalRoots = append(finalRoots, node.Root{
			Namespace: testNs,
			Version:   0,
			Type:      node.RootTypeState,
			Hash:      hash,
		})
	}
	err = ndb.Finalize(ctx, finalRoots)
	require.NoError(t, err, "Finalize")

	// Create a distinct root in version 1.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("different"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_1, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Create a derived root in version 1.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_2})
	err = tree.Insert(ctx, []byte("different2"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_2, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Create two linked roots inside version 1 which will not be referenced
	// in subsequent versions and so should be garbage collected.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("first"), []byte("am i"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_3, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_3})
	err = tree.Insert(ctx, []byte("second"), []byte("i am"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_4, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Create three linked roots inside version 1 where the first root is
	// derived from a root in version 0, the second root is derived from
	// the first root and the third root is derived from the second root
	// (both in the same version). All three should be garbage collected
	// as they are not referenced in subsequent versions.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_3})
	err = tree.Insert(ctx, []byte("first"), []byte("am i"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_5, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_5})
	err = tree.Insert(ctx, []byte("second"), []byte("i am"))
	require.NoError(t, err, "Insert")
	err = tree.Remove(ctx, []byte("yet"))
	require.NoError(t, err, "Remove")
	_, rootHashR1_6, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_6})
	err = tree.Insert(ctx, []byte("third"), []byte("i am not"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_7, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Create three linked roots inside version 1 where the first root is
	// derived from a root in version 0, the second root is derived from
	// the first root and the third root is derived from the second root
	// (both in the same version). The third root is then referenced in version
	// 2 so only intermediate nodes should be garbage collected.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_4})
	err = tree.Insert(ctx, []byte("first2"), []byte("am i"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_8, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_8})
	err = tree.Insert(ctx, []byte("second2"), []byte("i am"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_9, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_9})
	err = tree.Insert(ctx, []byte("third2"), []byte("i am not"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_10, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")
	// After these commits, 3 nodes are only referenced in intermediate roots
	// and should be garbage collected.

	// Finalize version 1.
	finalRoots = nil
	for _, hash := range []hash.Hash{rootHashR1_1, rootHashR1_2, rootHashR1_4, rootHashR1_7, rootHashR1_10} {
		finalRoots = append(finalRoots, node.Root{
			Namespace: testNs,
			Version:   1,
			Type:      node.RootTypeState,
			Hash:      hash,
		})
	}
	err = ndb.Finalize(ctx, finalRoots)
	require.NoError(t, err, "Finalize")

	// Create a distinct root in version 2.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("blah"), []byte("brah"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_1, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")

	// Create a derived root in version 2.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_2})
	err = tree.Insert(ctx, []byte("foo"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_2, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")

	// Create another derived root in version 2.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 1, Type: node.RootTypeState, Hash: rootHashR1_10})
	err = tree.Insert(ctx, []byte("foo2"), []byte("boo"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_3, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")

	// Finalize version 2.
	finalRoots = nil
	for _, hash := range []hash.Hash{rootHashR2_1, rootHashR2_2, rootHashR2_3} {
		finalRoots = append(finalRoots, node.Root{
			Namespace: testNs,
			Version:   2,
			Type:      node.RootTypeState,
			Hash:      hash,
		})
	}
	err = ndb.Finalize(ctx, finalRoots)
	require.NoError(t, err, "Finalize")

	// Prune versions 0 and 1, all of the lone root's node should have been removed.
	err = ndb.Prune(ctx, 0)
	require.NoError(t, err, "Prune")
	err = ndb.Prune(ctx, 1)
	require.NoError(t, err, "Prune")

	// Reopen database to force compaction.
	ndb.Close()
	ndb, err = factory(testNs)
	require.NoError(t, err, "ndb.New")
	defer ndb.Close()

	// Check that roots in version 0 and 2 are still there.
	for _, root := range []struct {
		Version uint64
		Hash    hash.Hash
		Keys    []string
	}{
		{2, rootHashR2_1, []string{"blah"}},
		{2, rootHashR2_2, []string{"goo", "different2", "foo"}},
		{2, rootHashR2_3, []string{"yet2", "first2", "second2", "third2", "foo2"}},
	} {
		tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: root.Version, Type: node.RootTypeState, Hash: root.Hash})

		for _, key := range root.Keys {
			value, err := tree.Get(ctx, []byte(key))
			require.NoError(t, err, "Get(%d, %s)", root.Version, key)
			require.NotNil(t, value, "value should exist (%d, %s)", root.Version, key)
		}
	}
}

func testErrors(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()

	// Commit root for version 0.
	tree := New(nil, ndb, node.RootTypeState)
	err := tree.Insert(ctx, []byte("foo"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHashR0_1, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")

	// Commit root for version 1.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("another"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHashR1_1, err := tree.Commit(ctx, testNs, 1)
	require.NoError(t, err, "Commit")

	// Commit root for version 2.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("another2"), []byte("bar"))
	require.NoError(t, err, "Insert")
	_, rootHashR2_1, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")

	// Commit for non-following version should fail.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 2, Type: node.RootTypeState, Hash: rootHashR2_1})
	err = tree.Insert(ctx, []byte("moo"), []byte("moo"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 100)
	require.Error(t, err, "Commit should fail for non-following version")
	require.Equal(t, db.ErrRootMustFollowOld, err)

	// Commit with mismatched old root should fail.
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 99, Type: node.RootTypeState, Hash: rootHashR1_1})
	err = tree.Insert(ctx, []byte("moo"), []byte("moo"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 100)
	require.Error(t, err, "Commit should fail for mismatched version")
	require.Equal(t, db.ErrRootNotFound, err)

	// Commit with non-existent old root should fail.
	bogusRoot := hash.NewFromBytes([]byte("bogus root"))
	tree = NewWithRoot(nil, ndb, node.Root{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: bogusRoot})
	_, _, err = tree.Commit(ctx, testNs, 1)
	require.Error(t, err, "Commit should fail for invalid root")
	require.Equal(t, db.ErrRootNotFound, err)

	// Finalizing a version twice should fail.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_1}})
	require.NoError(t, err, "Finalize")
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 0, Type: node.RootTypeState, Hash: rootHashR0_1}})
	require.Error(t, err, "Finalize should fail as version is already finalized")
	require.Equal(t, db.ErrAlreadyFinalized, err)

	// Finalize of version 2 should fail as version 1 is not finalized.
	err = ndb.Finalize(ctx, []node.Root{{Namespace: testNs, Version: 2, Type: node.RootTypeState, Hash: rootHashR2_1}})
	require.Error(t, err, "Finalize should fail as previous version not finalized")
	require.Equal(t, db.ErrNotFinalized, err)

	// Commit into an already finalized version should fail.
	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("already finalized"), []byte("woohoo"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, testNs, 0)
	require.Error(t, err, "Commit should fail for already finalized version")
	require.Equal(t, db.ErrAlreadyFinalized, err)

	// Commit for a different namespace should fail.
	var badNs common.Namespace
	_ = badNs.UnmarshalText([]byte("badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb"))

	tree = New(nil, ndb, node.RootTypeState)
	err = tree.Insert(ctx, []byte("bad namespace"), []byte("woohoo"))
	require.NoError(t, err, "Insert")
	_, _, err = tree.Commit(ctx, badNs, 0)
	require.Error(t, err, "Commit should fail for bad namespace")
	require.Equal(t, db.ErrBadNamespace, err)

	// Using the WithoutWriteLog option together with a remote read syncer should panic.
	require.Panics(t, func() { New(tree, nil, node.RootTypeState, WithoutWriteLog()) })
}

func testIncompatibleDB(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	// Database has been created with namespace testNs.
	ndb.Close()

	// Try to open the same database with a different namespace.
	testNs2 := common.NewTestNamespaceFromSeed([]byte("oasis mkvs test ns 2"), 0)
	_, err := factory(testNs2)
	require.Error(t, err, "using a different namespace should fail")
}

func testSpecialCaseFromJSON(t *testing.T, ndb db.NodeDB, fixture string) {
	data, err := ioutil.ReadFile(filepath.Join("testdata", fixture))
	require.NoError(t, err, "failed to read the fixture file")

	var ops mkvsTests.TestVector
	err = json.Unmarshal(data, &ops)
	require.NoError(t, err, "failed to unmarshal fixture")

	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	// Also test all operations against a "remote" tree to test sync operations.
	var root node.Root
	var remoteTree Tree
	var value []byte

	commitRemote := func() {
		// Commit everything and create a new remote tree at the root.
		var rootHash hash.Hash
		_, rootHash, err = tree.Commit(ctx, testNs, 0)
		require.NoError(t, err, "Commit")
		root = node.Root{Namespace: testNs, Type: node.RootTypeState, Hash: rootHash}
		remoteTree = NewWithRoot(tree, nil, root, Capacity(0, 0))
	}

	for _, o := range ops {
		switch o.Op {
		case mkvsTests.OpInsert:
			if remoteTree != nil {
				err = remoteTree.Insert(ctx, o.Key, o.Value)
				require.NoError(t, err, "Insert")
			}

			err = tree.Insert(ctx, o.Key, o.Value)
			require.NoError(t, err, "Insert")

			commitRemote()
		case mkvsTests.OpRemove:
			if remoteTree != nil {
				err = remoteTree.Remove(ctx, o.Key)
				require.NoError(t, err, "Remove")
				value, err = remoteTree.Get(ctx, o.Key)
				require.NoError(t, err, "Get (after Remove)")
				require.Nil(t, value, "Get (after Remove) should return nil")
			}

			err = tree.Remove(ctx, o.Key)
			require.NoError(t, err, "Remove")
			value, err = tree.Get(ctx, o.Key)
			require.NoError(t, err, "Get (after Remove)")
			require.Nil(t, value, "Get (after Remove) should return nil")

			commitRemote()
		case mkvsTests.OpGet:
			if remoteTree != nil {
				value, err = remoteTree.Get(ctx, o.Key)
				require.NoError(t, err, "Get")
				require.EqualValues(t, o.Value, value, "Get should return the correct value")
			}

			value, err = tree.Get(ctx, o.Key)
			require.NoError(t, err, "Get")
			require.EqualValues(t, o.Value, value, "Get should return the correct value")
		case mkvsTests.OpIteratorSeek:
			if remoteTree != nil {
				it := remoteTree.NewIterator(ctx)
				it.Seek(o.Key)
				require.NoError(t, it.Err(), "Seek")
				require.EqualValues(t, o.ExpectedKey, it.Key(), "iterator should be at correct key")
				require.EqualValues(t, o.Value, it.Value(), "iterator should be at correct value")
				it.Close()
			}

			it := tree.NewIterator(ctx)
			it.Seek(o.Key)
			require.NoError(t, it.Err(), "Seek")
			require.EqualValues(t, o.ExpectedKey, it.Key(), "iterator should be at correct key")
			require.EqualValues(t, o.Value, it.Value(), "iterator should be at correct value")
			it.Close()
		default:
			require.Fail(t, "unknown operation: %s", o.Op)
		}
	}
}

func testSpecialCase1(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	testSpecialCaseFromJSON(t, ndb, "case-1.json")
}

func testSpecialCase2(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	testSpecialCaseFromJSON(t, ndb, "case-2.json")
}

func testSpecialCase3(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	testSpecialCaseFromJSON(t, ndb, "case-3.json")
}

func testSpecialCase4(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	testSpecialCaseFromJSON(t, ndb, "case-4.json")
}

func testSpecialCase5(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	testSpecialCaseFromJSON(t, ndb, "case-5.json")
}

func testLargeUpdates(t *testing.T, ndb db.NodeDB, factory NodeDBFactory) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState)

	// The number of elements is such that it would overflow the maximum number of allowed array
	// elements in the default (untrusted) CBOR decoder.
	for i := 0; i < 132_000; i++ {
		err := tree.Insert(ctx, []byte(fmt.Sprintf("%d", i)), []byte(fmt.Sprintf("%d", i)))
		require.NoError(t, err, "Insert")
	}

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	root := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}
	err = ndb.Finalize(ctx, []node.Root{root})
	require.NoError(t, err, "Finalize")
}

func testBackend(
	t *testing.T,
	initBackend func(t *testing.T) (NodeDBFactory, func()),
	skipTests []string,
) {
	tests := []struct {
		name string
		fn   func(*testing.T, db.NodeDB, NodeDBFactory)
	}{
		{"Basic", testBasic},
		{"LongKeys", testLongKeys},
		{"EmptyKeys", testEmptyKeys},
		{"InsertCommitBatch", testInsertCommitBatch},
		{"InsertCommitEach", testInsertCommitEach},
		{"Remove", testRemove},
		{"ApplyWriteLog", testApplyWriteLog},
		{"SyncerBasic", testSyncerBasic},
		{"SyncerRootEmptyLabelNeedsDeref", testSyncerRootEmptyLabelNeedsDeref},
		{"SyncerRemove", testSyncerRemove},
		{"SyncerInsert", testSyncerInsert},
		{"SyncerNilNodes", testSyncerNilNodes},
		{"SyncerPrefetchPrefixes", testSyncerPrefetchPrefixes},
		{"ValueEviction", testValueEviction},
		{"NodeEviction", testNodeEviction},
		{"DoubleInsertWithEviction", testDoubleInsertWithEviction},
		{"DebugDump", testDebugDumpLocal},
		{"OnCommitHooks", testOnCommitHooks},
		{"CommitNoPersist", testCommitNoPersist},
		{"MergeWriteLog", testMergeWriteLog},
		{"HasRoot", testHasRoot},
		{"GetRootsForVersion", testGetRootsForVersion},
		{"Size", testSize},
		{"PruneBasic", testPruneBasic},
		{"PruneManyVersions", testPruneManyVersions},
		{"PruneLoneRoots", testPruneLoneRoots},
		{"PruneLoneRootsShared", testPruneLoneRootsShared},
		{"PruneLoneRootsShared2", testPruneLoneRootsShared2},
		{"PruneLoneRootsShared3", testPruneLoneRootsShared3},
		{"PruneLoneRootsShared4", testPruneLoneRootsShared4},
		{"PruneForkedRoots", testPruneForkedRoots},
		{"SpecialCase1", testSpecialCase1},
		{"SpecialCase2", testSpecialCase2},
		{"SpecialCase3", testSpecialCase3},
		{"SpecialCase4", testSpecialCase4},
		{"SpecialCase5", testSpecialCase5},
		{"LargeUpdates", testLargeUpdates},
		{"Errors", testErrors},
		{"IncompatibleDB", testIncompatibleDB},
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

			factory, cleanup := initBackend(t)
			backend, err := factory(testNs)
			require.NoError(t, err, "ndb.New")
			defer cleanup()
			tc.fn(t, backend, factory)
		})
	}
}

func TestBadgerBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (NodeDBFactory, func()) {
		// Create a new random temporary directory under /tmp.
		dir, err := ioutil.TempDir("", "mkvs.test.badger")
		require.NoError(t, err, "TempDir")

		// Create a Badger-backed Node DB factory.
		factory := func(ns common.Namespace) (db.NodeDB, error) {
			return badgerDb.New(&db.Config{
				DB:           dir,
				NoFsync:      true,
				Namespace:    ns,
				MaxCacheSize: 16 * 1024 * 1024,
			})
		}

		cleanup := func() {
			os.RemoveAll(dir)
		}

		return factory, cleanup
	}, nil)
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
		dir, err := ioutil.TempDir("", "mkvs.bench.badgerdb")
		require.NoError(b, err, "TempDir")
		defer os.RemoveAll(dir)
		ndb, err := badgerDb.New(&db.Config{
			DB:           dir,
			Namespace:    testNs,
			MaxCacheSize: 16 * 1024 * 1024,
		})
		require.NoError(b, err, "New")
		tree := New(nil, ndb, node.RootTypeState)

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

func generateLongKeyValuePairs() ([][]byte, [][]byte) {
	keys := make([][]byte, len(longKey))
	values := make([][]byte, len(longKey))
	for i := 0; i < len(longKey); i++ {
		keys[i] = []byte(longKey[0 : i+1])
		values[i] = []byte(longValue)
	}

	return keys, values
}

func generatePopulatedTree(t *testing.T, ndb db.NodeDB) ([][]byte, [][]byte, node.Root, Tree) {
	ctx := context.Background()
	tree := New(nil, ndb, node.RootTypeState, Capacity(0, 0))

	keys, values := generateKeyValuePairs()
	for i := 0; i < len(keys); i++ {
		err := tree.Insert(ctx, keys[i], values[i])
		require.NoError(t, err, "Insert")
	}

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(t, err, "Commit")
	require.Equal(t, allItemsRoot, rootHash.String())

	root := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}
	return keys, values, root, tree
}
