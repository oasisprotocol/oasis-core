package mkvs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pathbadger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// // useful for debugging only
// func TestSubtree(t *testing.T) {
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
// 	for _, i := range []int{1} {
// 		err = tr.Insert(ctx, []byte(strconv.Itoa(i)), []byte(strconv.Itoa(i)))
// 		require.NoError(err, "Insert")
// 	}

// 	_, rootHash, err := tr.Commit(ctx, testNs, 2)
// 	require.NoError(err)

// 	// iterator := tr.NewIterator(ctx)

// 	// for iterator.Seek(node.Key{}); iterator.Valid(); iterator.Next() {
// 	// 	key, _ := hex.DecodeString(iterator.Key().String())
// 	// 	fmt.Printf("key: %s, %s, value: %s\n", key, iterator.Key().String(), iterator.Value())
// 	// }

// 	// tr.DumpLocal(ctx, os.Stdout, 4)
// 	subtrees, err := tr.Subtrees(ctx, 1)

// 	fmt.Println(len(subtrees))
// 	for i, s := range subtrees {
// 		it := s.Iterator(ctx, syncer.NewProofBuilderV0(rootHash, rootHash))
// 		fmt.Printf("Iterator %d\n", i)
// 		for it.Rewind(); it.Valid(); it.Next() {
// 			key, _ := hex.DecodeString(it.Key().String())
// 			fmt.Printf("key: %s, %s, value: %s\n", key, it.Key().String(), it.Value())

// 		}
// 	}

// }

// TODO:
// 1. Make this test nicer
// 2. Fuzz!
// 3. Test proofs for subtrees are correct (also fuzz).

func TestSubtreeIterator(t *testing.T) {
	testCases := []struct {
		insert []int
		depth  int
	}{
		{
			insert: []int{1},
			depth:  1,
		},
		{
			insert: []int{1},
			depth:  2,
		},
		{
			insert: []int{1, 11, 12},
			depth:  1,
		},
		{
			insert: []int{1, 11, 12},
			depth:  2,
		},
		{
			insert: []int{1, 11, 12, 122, 123},
			depth:  1,
		},
		{
			insert: []int{1, 11, 12, 122, 123},
			depth:  2,
		},
	}

	for _, tc := range testCases {
		ctx := context.Background()

		dir, err := os.MkdirTemp("", "mkvs.subtreeIterator")
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

		tr := New(nil, ndb, node.RootTypeState)
		var inserted []string
		for _, i := range tc.insert {
			key := []byte(strconv.Itoa(i))
			if err = tr.Insert(ctx, key, []byte(strconv.Itoa(i))); err != nil {
				t.Fatalf("failed to insert %q: %v", key, err)
			}
			inserted = append(inserted, string(key))
		}

		_, rootHash, err := tr.Commit(ctx, testNs, 1)
		if err != nil {
			t.Fatalf("failed to commit in-memory tree: %v", err)
		}

		subtrees, err := tr.Subtrees(ctx, tc.depth)
		if err != nil {
			t.Fatalf("failed to get subtrees for depth %d: %v", tc.depth, err)
		}

		var iterated []string
		for _, st := range subtrees {
			it := st.Iterator(ctx, syncer.NewProofBuilderV0(rootHash, rootHash))
			for it.Rewind(); it.Valid(); it.Next() {
				iterated = append(iterated, string(it.Key()))
			}
		}

		slices.Sort(inserted)
		slices.Sort(iterated)

		if !slices.Equal(inserted, iterated) {
			t.Errorf("inserted: %v but only iterated over: %v", inserted, iterated)
		}

	}

}
