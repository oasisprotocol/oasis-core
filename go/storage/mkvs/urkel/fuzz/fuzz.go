// +build gofuzz

package fuzz

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	commonFuzz "github.com/oasislabs/oasis-core/go/common/fuzz"
	mkvs "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel"
	mkvsTests "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/tests"
)

var (
	tree *TreeFuzz

	fuzzer *commonFuzz.InterfaceFuzzer
)

// TreeFuzz is a wrapper around a mkvs.KeyValueTree for fuzzing purposes.
type TreeFuzz struct {
	inner     mkvs.KeyValueTree
	reference map[string][]byte
	history   mkvsTests.TestVector
}

func (t *TreeFuzz) Insert(ctx context.Context, key []byte, value []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	if err := t.inner.Insert(ctx, key, value); err != nil {
		t.fail("Insert failed: %s", err)
	}

	// Make sure the key has been set.
	if getValue, err := t.inner.Get(ctx, key); err != nil || !bytes.Equal(value, getValue) {
		t.fail("Insert check failed: %s", err)
	}

	t.reference[string(key)] = value
	t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpInsert, Key: key, Value: value})
	return 0
}

func (t *TreeFuzz) Get(ctx context.Context, key []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	value, err := t.inner.Get(ctx, key)
	if err != nil {
		t.fail("Get failed: %s", err)
	}

	t.assertCorrectValue(key, value)

	return 0
}

func (t *TreeFuzz) RemoveExisting(ctx context.Context, key []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	value, err := t.inner.RemoveExisting(ctx, key)
	if err != nil {
		t.fail("RemoveExisting failed: %s", err)
	}

	// Make sure the key has been removed.
	if value, err := t.inner.Get(ctx, key); err != nil || value != nil {
		t.fail("RemoveExisting check failed: %s", err)
	}

	t.assertCorrectValue(key, value)

	delete(t.reference, string(key))
	t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpRemove, Key: key})

	return 0
}

func (t *TreeFuzz) Remove(ctx context.Context, key []byte) int {
	if len(key) == 0 {
		// Ignore zero-length keys as they are invalid.
		return -1
	}

	if err := t.inner.Remove(ctx, key); err != nil {
		t.fail("Remove failed: %s", err)
	}

	// Make sure the key has been removed.
	if value, err := t.inner.Get(ctx, key); err != nil || value != nil {
		t.fail("Remove check failed: %s", err)
	}

	delete(t.reference, string(key))
	t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpRemove, Key: key})

	return 0
}

func (t *TreeFuzz) IteratorSeek(ctx context.Context, key []byte) int {
	it := t.inner.NewIterator(ctx)
	defer it.Close()

	it.Seek(key)
	if it.Err() != nil {
		t.fail("IteratorSeek failed: %s", it.Err())
	}

	// Check that the iterator is in the correct position.
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
	if !bytes.Equal(expectedKey, it.Key()) || !bytes.Equal(expectedValue, it.Value()) {
		// Add the final IteratorSeek operation.
		t.history = append(t.history, &mkvsTests.Op{
			Op:          mkvsTests.OpIteratorSeek,
			Key:         key,
			Value:       expectedValue,
			ExpectedKey: expectedKey,
		})

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
		// Add the final Get operation.
		t.history = append(t.history, &mkvsTests.Op{Op: mkvsTests.OpGet, Key: key, Value: refValue})

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
	fmt.Printf("%s\n", history)
	fmt.Printf("------------------------------------------\n")

	panic(fmt.Sprintf(format, a...))
}

func NewTreeFuzz() *TreeFuzz {
	return &TreeFuzz{
		inner:     mkvs.New(nil, nil, mkvs.WithoutWriteLog()),
		reference: make(map[string][]byte),
	}
}

func init() {
	// Create the in-memory tree.
	tree = NewTreeFuzz()

	// Create and prepare the fuzzer.
	fuzzer = commonFuzz.NewInterfaceFuzzer(tree)
}

func Fuzz(data []byte) int {
	values, result := fuzzer.DispatchBlob(data)
	if !result {
		return -1
	}

	// Return value is another result.
	return values[0].Interface().(int)
}
