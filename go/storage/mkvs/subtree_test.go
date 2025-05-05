package mkvs

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pathbadger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// TODO:
// 1. Code quality
// 2. Test proofs for subtrees are correct (also fuzz).
func FuzzSubtreeIteratorSeqNums(f *testing.F) {
	f.Add(uint16(1000), uint8(7))
	testcases := []struct {
		n     uint16
		depth uint8
	}{
		{
			n:     0,
			depth: 0,
		},
		{
			n:     0,
			depth: 1,
		},
		{
			n:     64,
			depth: 2,
		},

		{
			n:     1000,
			depth: 7,
		},
		{
			n:     1000,
			depth: 0,
		},
		{
			n:     40,
			depth: 0,
		},
		{
			n:     40000,
			depth: 12,
		},
	}

	for _, tc := range testcases {
		f.Add(tc.n, tc.depth)
	}

	f.Fuzz(func(t *testing.T, n uint16, depth uint8) {
		ctx := context.Background()
		// TODO if depth is higher we run out of cache:
		//    - either limit depth via error or safer subtree generation.
		depth = depth % 15

		dir, err := os.MkdirTemp("", "mkvs.IterableSubtree")
		if err != nil {
			t.Fatalf("failed to created new temporay dir: %v", err)
		}
		defer os.RemoveAll(dir)

		cfg := &api.Config{
			DB:           filepath.Join(dir, "db"),
			Namespace:    testNs,
			MaxCacheSize: 16 * 1024 * 1024,
		}
		ndb, err := pathbadger.New(cfg)
		if err != nil {
			t.Fatalf("failed to create new pathbadger backend: %v", err)
		}
		defer ndb.Close()

		keys := make([][]byte, 0, n)
		inserted := make([]string, 0, n)
		for i := uint16(0); i < n; i++ {
			key := []byte(strconv.Itoa(int(i)))
			keys = append(keys, key)
			inserted = append(inserted, string(key))
		}

		root := populateDb(ctx, t, ndb, testNs, keys)

		subtrees, err := NewIterSubtrees(ctx, ndb, root, int(depth))
		if err != nil {
			t.Fatalf("failed to get subtrees for depth %d: %v", depth, err)
		}
		defer func() {
			for _, s := range subtrees {
				s.Close()
			}
		}()

		iterated := make([]string, 0, n)
		fmt.Println(len(subtrees))
		for _, st := range subtrees {
			it := st.Iterator(ctx, syncer.NewProofBuilderV0(root.Hash, root.Hash))
			defer it.Close()
			for it.Rewind(); it.Valid(); it.Next() {
				iterated = append(iterated, string(it.Key()))
			}
		}

		slices.Sort(inserted)
		slices.Sort(iterated)

		if diff := cmp.Diff(inserted, iterated); diff != "" {
			t.Error(diff)
		}
	})
}

func populateDb(ctx context.Context, t *testing.T, ndb api.NodeDB, ns common.Namespace, keys [][]byte) node.Root {
	t.Helper()

	tree := New(nil, ndb, node.RootTypeState)
	for i, key := range keys {
		val := []byte(strconv.Itoa(int(i)))
		if err := tree.Insert(ctx, key, val); err != nil {
			t.Fatalf("Insert(%x, %x): %v", key, val, err)
		}
	}

	version := 1
	_, rootHash, err := tree.Commit(ctx, ns, uint64(version))
	if err != nil {
		t.Fatalf("Commit(%.8s, %d): %v", ns, version, err)
	}

	root := node.Root{
		Namespace: ns,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}

	return root
}

// useful for debugging will be removed
// func TestSubtreeDebug(t *testing.T) {
// 	require := require.New(t)

// 	dir, err := os.MkdirTemp("", "mkvs.checkpoint")
// 	require.NoError(err, "TempDir")
// 	defer os.RemoveAll(dir)

// 	cfg := &api.Config{
// 		DB:           filepath.Join(dir, "db"),
// 		Namespace:    testNs,
// 		MaxCacheSize: 16 * 1024 * 1024,
// 	}

// 	ndb, err := pathbadger.New(cfg)
// 	require.NoError(err, "New")

// 	ctx := context.Background()
// 	tr := New(nil, ndb, node.RootTypeState)
// 	for i := 0; i < 10015; i++ {
// 		err = tr.Insert(ctx, []byte(strconv.Itoa(i)), []byte(strconv.Itoa(i)))
// 		require.NoError(err, "Insert")
// 	}

// 	_, rootHash, err := tr.Commit(ctx, testNs, 2)
// 	require.NoError(err)

// 	root := node.Root{
// 		Namespace: testNs,
// 		Version:   2,
// 		Type:      node.RootTypeState,
// 		Hash:      rootHash,
// 	}

// 	iterator := tr.NewIterator(ctx)

// 	for iterator.Rewind(); iterator.Valid(); iterator.Next() {
// 	}

// 	tr.DumpLocal(ctx, os.Stdout, 10)
// 	subtrees, err := NewIterSubtrees(ctx, ndb, root, 0)

// 	fmt.Println(len(subtrees))
// 	for i, s := range subtrees {
// 		max := 0
// 		it := s.Iterator(ctx, syncer.NewProofBuilderV0(rootHash, rootHash))
// 		fmt.Printf("Iterator %d\n", i)
// 		for it.Rewind(); it.Valid(); it.Next() {
// 			if max < 10 {
// 				key, _ := hex.DecodeString(it.Key().String())
// 				fmt.Printf("key: %s, %s, value: %s\n", key, it.Key().String(), it.Value())
// 				max++

// 			}

// 		}
// 	}

// }

// Useful for debugging will be removed.
// func TestSubtreeIterator(t *testing.T) {

// 	var bigtree []int
// 	for i := 0; i < 10041; i++ {
// 		bigtree = append(bigtree, i)
// 	}
// 	testCases := []struct {
// 		insert []int
// 		depth  int
// 	}{
// 		// {
// 		// 	insert: []int{},
// 		// 	depth:  0,
// 		// },
// 		// {
// 		// 	insert: []int{1},
// 		// 	depth:  0,
// 		// },
// 		// {
// 		// 	insert: []int{1},
// 		// 	depth:  2,
// 		// },
// 		// {
// 		// 	insert: []int{1, 11, 12},
// 		// 	depth:  1,
// 		// },
// 		// {
// 		// 	insert: []int{1, 11, 12},
// 		// 	depth:  12,
// 		// },
// 		// {
// 		// 	insert: []int{1, 11, 12, 122, 123},
// 		// 	depth:  1,
// 		// },
// 		// {
// 		// 	insert: []int{1, 11, 12, 122, 123},
// 		// 	depth:  2,
// 		// },
// 		{
// 			insert: bigtree,
// 			depth:  16,
// 		},
// 	}

// 	for _, tc := range testCases {
// 		ctx := context.Background()

// 		dir, err := os.MkdirTemp("", "mkvs.subtreeIterator")
// 		if err != nil {
// 			t.Fatalf("failed to created new temporay dir: %v", err)
// 		}
// 		defer os.RemoveAll(dir)

// 		cfg := &api.Config{
// 			DB:           filepath.Join(dir, "db"),
// 			Namespace:    testNs,
// 			MaxCacheSize: 16 * 1024 * 1024,
// 		}
// 		ndb, err := pathbadger.New(cfg)
// 		if err != nil {
// 			t.Fatalf("failed to create new pathbadger backend: %v", err)
// 		}
// 		defer ndb.Close()

// 		var inserted []string

// 		keys := make([][]byte, 0, len(tc.insert))
// 		for _, key := range tc.insert {
// 			keys = append(keys, []byte(strconv.Itoa(int(key))))
// 			inserted = append(inserted, string(strconv.Itoa(key)))

// 		}

// 		root := populateDb(ctx, t, ndb, testNs, keys)

// 		subtrees, err := NewIterSubtrees(ctx, ndb, root, tc.depth)
// 		if err != nil {
// 			t.Fatalf("failed to get subtrees for depth %d: %v", tc.depth, err)
// 		}
// 		defer func() {
// 			for _, s := range subtrees {
// 				s.Close()
// 			}
// 		}()

// 		var iterated []string
// 		fmt.Println(len(subtrees))
// 		for _, st := range subtrees {
// 			// fmt.Println(st.String())
// 			it := st.Iterator(ctx, syncer.NewProofBuilderV0(root.Hash, root.Hash))
// 			defer it.Close()
// 			for it.Rewind(); it.Valid(); it.Next() {

// 				// if it.Key().Equal([]byte("0")) {
// 				// 	fmt.Println("here")
// 				// }
// 				// fmt.Println(it.Key())
// 				iterated = append(iterated, string(it.Key()))
// 			}
// 		}

// 		slices.Sort(inserted)
// 		slices.Sort(iterated)

// 		if diff := cmp.Diff(inserted, iterated); diff != "" {
// 			t.Error(diff)
// 		}
// 	}
// }
