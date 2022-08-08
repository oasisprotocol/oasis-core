package mkvs

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/tests"
)

const (
	// OpInsert is the tree insert operation name.
	OpInsert = 0
	// OpRemove is the tree remove operation name.
	OpRemove = 1
	// OpGet is the tree get operation name.
	OpGet = 2
	// OpIteratorSeek is the tree iterator seek operation name.
	OpIteratorSeek = 3
)

// Op is a tree operation used in test vectors.
type Op struct {
	// Op is the operation name.
	Op uint8 `json:"op"`
	// Key is the key that is inserted, removed or looked up.
	Key []byte `json:"key"`
	// Value is the value that is inserted.
	Value []byte `json:"value"`
}

func convertFromTestVector(fn string) []byte {
	raw, err := ioutil.ReadFile(fn)
	if err != nil {
		panic(err)
	}

	var tv tests.TestVector
	err = json.Unmarshal(raw, &tv)
	if err != nil {
		panic(err)
	}

	var ops []Op
	for _, op := range tv {
		var convOp uint8
		switch op.Op {
		case tests.OpInsert:
			convOp = 0
		case tests.OpRemove:
			convOp = 1
		case tests.OpGet:
			convOp = 2
		case tests.OpIteratorSeek:
			convOp = 3
		default:
			panic("unknown op")
		}

		ops = append(ops, Op{Op: convOp, Key: op.Key, Value: op.Value})
	}

	return cbor.Marshal(ops)
}

func FuzzTree(f *testing.F) {
	// Seed corpus.
	f.Add(convertFromTestVector("testdata/case-1.json"))
	f.Add(convertFromTestVector("testdata/case-2.json"))
	f.Add(convertFromTestVector("testdata/case-3.json"))
	f.Add(convertFromTestVector("testdata/case-4.json"))
	f.Add(convertFromTestVector("testdata/case-5.json"))

	// Fuzzing.
	f.Fuzz(func(t *testing.T, data []byte) {
		var ops []Op
		err := cbor.Unmarshal(data, &ops)
		if err != nil {
			return
		}

		ctx := context.Background()
		tree := New(nil, nil, node.RootTypeState)

		// Also test all operations against a "remote" tree to test sync operations.
		var root node.Root
		var remoteTree Tree
		var value []byte
		reference := make(map[string][]byte)

		commitRemote := func() {
			// Commit everything and create a new remote tree at the root.
			var rootHash hash.Hash
			_, rootHash, err = tree.Commit(ctx, testNs, 0)
			require.NoError(t, err, "Commit")
			root = node.Root{Namespace: testNs, Type: node.RootTypeState, Hash: rootHash}
			remoteTree = NewWithRoot(tree, nil, root, Capacity(0, 0))
		}

		for _, o := range ops {
			if len(o.Key) == 0 {
				// Ignore zero-length keys as they are invalid.
				continue
			}
			if o.Value == nil {
				// Perform the same conversion that is performed internally by tree insert.
				o.Value = []byte{}
			}

			switch o.Op {
			case OpInsert:
				if remoteTree != nil {
					err = remoteTree.Insert(ctx, o.Key, o.Value)
					require.NoError(t, err, "Insert")
				}

				err = tree.Insert(ctx, o.Key, o.Value)
				require.NoError(t, err, "Insert")

				reference[string(o.Key)] = o.Value

				commitRemote()
			case OpRemove:
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

				delete(reference, string(o.Key))

				commitRemote()
			case OpGet:
				expectedValue := reference[string(o.Key)]

				if remoteTree != nil {
					value, err = remoteTree.Get(ctx, o.Key)
					require.NoError(t, err, "Get")
					require.EqualValues(t, expectedValue, value, "Get should return the correct value")
				}

				value, err = tree.Get(ctx, o.Key)
				require.NoError(t, err, "Get")
				require.EqualValues(t, expectedValue, value, "Get should return the correct value")
			case OpIteratorSeek:
				var ordered []string
				for k := range reference {
					ordered = append(ordered, k)
				}
				sort.Strings(ordered)

				var expectedKey, expectedValue []byte
				for _, k := range ordered {
					if k >= string(o.Key) {
						expectedKey = []byte(k)
						expectedValue = reference[k]
						break
					}
				}

				if remoteTree != nil {
					it := remoteTree.NewIterator(ctx)
					it.Seek(o.Key)
					require.NoError(t, it.Err(), "Seek")
					require.EqualValues(t, expectedKey, it.Key(), "iterator should be at correct key")
					require.EqualValues(t, expectedValue, it.Value(), "iterator should be at correct value")
					it.Close()
				}

				it := tree.NewIterator(ctx)
				it.Seek(o.Key)
				require.NoError(t, it.Err(), "Seek")
				require.EqualValues(t, expectedKey, it.Key(), "iterator should be at correct key")
				require.EqualValues(t, expectedValue, it.Value(), "iterator should be at correct value")
				it.Close()
			}
		}
	})
}
