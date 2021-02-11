// +build gofuzz

package fuzz

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sort"

	"github.com/oasisprotocol/oasis-core/go/common"
	commonFuzz "github.com/oasisprotocol/oasis-core/go/common/fuzz"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	mkvsNode "github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	mkvsTests "github.com/oasisprotocol/oasis-core/go/storage/mkvs/tests"
)

var treeFuzzer *commonFuzz.InterfaceFuzzer

// TreeFuzz is a wrapper around a mkvs.Tree for fuzzing purposes.
//
// The fuzzer works against two trees, an "inner" one and a "remote" one. Both trees are only
// in-memory and do not use a node database. The "remote" tree talks to the "inner" tree via the
// ReadSyncer interface in order to fuzz that part as well.
//
//   remote <-- ReadSyncer --> inner
//
// Because there is no database, the remote tree can only access the root hash that was committed
// last and the inner tree must never be dirty. This means that all mutations must first be applied
// to the remote tree as otherwise the ReadSyncer operations would fail.
//
// This could be improved in the future by introducing a separate Commit operation, allowing the
// fuzzer to generate histories where multiple mutation operations are performed against the remote
// tree.
type TreeFuzz struct {
	inner  mkvs.Tree
	remote mkvs.Tree

	reference map[string][]byte
	history   mkvsTests.TestVector
}

func (t *TreeFuzz) commitRemote(ctx context.Context) {
	_, rootHash, err := t.inner.Commit(ctx, common.Namespace{}, 0)
	if err != nil {
		t.fail("CommitRemote failed: %s", err)
	}

	if t.remote != nil {
		t.remote.Close()
	}
	t.remote = mkvs.NewWithRoot(t.inner, nil, mkvsNode.Root{Type: mkvsNode.RootTypeState, Hash: rootHash}, mkvs.Capacity(0, 0))
}

func (t *TreeFuzz) insert(ctx context.Context, tree mkvs.Tree, key, value []byte) {
	if tree == nil {
		return
	}

	if err := tree.Insert(ctx, key, value); err != nil {
		t.fail("Insert failed: %s", err)
	}
}

func (t *TreeFuzz) Insert(ctx context.Context, key, value []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpInsert, Key: key, Value: value})

	t.insert(ctx, t.remote, key, value)
	t.insert(ctx, t.inner, key, value)

	if value == nil {
		// Perform the same conversion that is performed internally by tree insert.
		value = []byte{}
	}

	// Make sure the key has been set.
	if getValue, err := t.inner.Get(ctx, key); err != nil || !bytes.Equal(value, getValue) {
		t.fail("Insert check failed: %s", err)
	}

	t.reference[string(key)] = value

	t.commitRemote(ctx)

	return 0
}

func (t *TreeFuzz) get(ctx context.Context, tree mkvs.Tree, key []byte) {
	if tree == nil {
		return
	}

	value, err := tree.Get(ctx, key)
	if err != nil {
		t.fail("Get failed: %s", err)
	}

	t.assertCorrectValue(key, value)
}

func (t *TreeFuzz) Get(ctx context.Context, key []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpGet, Key: key, Value: t.reference[string(key)]})

	t.get(ctx, t.remote, key)
	t.get(ctx, t.inner, key)

	return 0
}

func (t *TreeFuzz) removeExisting(ctx context.Context, tree mkvs.Tree, key []byte) {
	if tree == nil {
		return
	}

	value, err := tree.RemoveExisting(ctx, key)
	if err != nil {
		t.fail("RemoveExisting failed: %s", err)
	}

	// Make sure the key has been removed.
	if value, err := tree.Get(ctx, key); err != nil || value != nil {
		t.fail("RemoveExisting check failed: %s", err)
	}

	t.assertCorrectValue(key, value)
}

func (t *TreeFuzz) RemoveExisting(ctx context.Context, key []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpRemove, Key: key})

	t.removeExisting(ctx, t.remote, key)
	t.removeExisting(ctx, t.inner, key)

	delete(t.reference, string(key))

	t.commitRemote(ctx)

	return 0
}

func (t *TreeFuzz) remove(ctx context.Context, tree mkvs.Tree, key []byte) {
	if tree == nil {
		return
	}

	if err := tree.Remove(ctx, key); err != nil {
		t.fail("Remove failed: %s", err)
	}

	// Make sure the key has been removed.
	if value, err := tree.Get(ctx, key); err != nil || value != nil {
		t.fail("Remove check failed: %s", err)
	}
}

func (t *TreeFuzz) Remove(ctx context.Context, key []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpRemove, Key: key})

	t.remove(ctx, t.remote, key)
	t.remove(ctx, t.inner, key)

	delete(t.reference, string(key))

	t.commitRemote(ctx)

	return 0
}

func (t *TreeFuzz) IteratorSeek(ctx context.Context, key []byte) int {
	var ordered []string
	for k := range t.reference {
		ordered = append(ordered, k)
	}
	sort.Strings(ordered)

	var expectedKey, expectedValue []byte
	for _, k := range ordered {
		if k >= string(key) {
			expectedKey = []byte(k)
			expectedValue = t.reference[k]
			break
		}
	}

	t.history = append(t.history, &mkvsTests.Op{
		Op:          mkvsTests.OpIteratorSeek,
		Key:         key,
		Value:       expectedValue,
		ExpectedKey: expectedKey,
	})

	it := t.inner.NewIterator(ctx)
	defer it.Close()

	it.Seek(key)
	if it.Err() != nil {
		t.fail("IteratorSeek failed: %s", it.Err())
	}

	// Check that the iterator is in the correct position.
	if !bytes.Equal(expectedKey, it.Key()) || !bytes.Equal(expectedValue, it.Value()) {
		t.fail("iterator Seek returned incorrect key/value (expected: %s/%s got: %s/%s)",
			hex.EncodeToString(expectedKey),
			hex.EncodeToString(expectedValue),
			hex.EncodeToString(it.Key()),
			hex.EncodeToString(it.Value()),
		)
	}

	return 0
}

func (t *TreeFuzz) assertCorrectValue(key, value []byte) {
	if refValue := t.reference[string(key)]; !bytes.Equal(value, refValue) {
		t.fail("Get returned incorrect value for key %s (expected: %s got: %s)",
			hex.EncodeToString(key),
			hex.EncodeToString(refValue),
			hex.EncodeToString(value),
		)
	}
}

func (t *TreeFuzz) fail(format string, a ...interface{}) {
	// In case there is a failure, dump the operation history so it can be used to create a test
	// vector for unit tests.
	fmt.Printf("--- FAILURE: Dumping operation history ---\n")

	history, _ := json.MarshalIndent(t.history, "", "    ")
	f, err := ioutil.TempFile("", "oasis-node-fuzz-mkvs-dump-*.json")
	if err == nil {
		_, _ = f.Write(history)
		f.Close()

		fmt.Printf("[see %s]\n", f.Name())
	} else {
		fmt.Printf("[unable to save dump: %s]", err.Error())
	}
	fmt.Printf("------------------------------------------\n")

	panic(fmt.Sprintf(format, a...))
}

func NewTreeFuzz() (*TreeFuzz, *commonFuzz.InterfaceFuzzer) {
	tf := &TreeFuzz{
		inner:     mkvs.New(nil, nil, mkvsNode.RootTypeState, mkvs.Capacity(0, 0)),
		reference: make(map[string][]byte),
	}
	fz := commonFuzz.NewInterfaceFuzzer(tf)
	return tf, fz
}

func init() {
	// Initialize stateful fuzzing state.
	_, treeFuzzer = NewTreeFuzz()
}

func FuzzTree(data []byte) int {
	values, result := treeFuzzer.DispatchBlob(data)
	if !result {
		return -1
	}

	// Return value is another result.
	return values[0].Interface().(int)
}
