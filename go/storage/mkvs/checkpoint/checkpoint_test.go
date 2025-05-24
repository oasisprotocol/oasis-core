package checkpoint

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db"
	dbApi "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pathbadger"
	dbTesting "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/testing"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

var testNs = common.NewTestNamespaceFromSeed([]byte("oasis mkvs checkpoint test ns"), 0)

func TestFileCheckpointCreator(t *testing.T) {
	dbTesting.TestMultipleBackends(t, db.Backends, testFileCheckpointCreator)
}

func testFileCheckpointCreator(t *testing.T, factory dbApi.Factory) {
	require := require.New(t)

	// Generate some data.
	dir, err := os.MkdirTemp("", "mkvs.checkpoint")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	ndb, err := factory.New(&dbApi.Config{
		DB:           filepath.Join(dir, "db"),
		Namespace:    testNs,
		MaxCacheSize: 16 * 1024 * 1024,
	})
	require.NoError(err, "New")

	ctx := context.Background()
	tree := mkvs.New(nil, ndb, node.RootTypeState)
	for i := 0; i < 1000; i++ {
		err = tree.Insert(ctx, []byte(strconv.Itoa(i)), []byte(strconv.Itoa(i)))
		require.NoError(err, "Insert")
	}

	_, rootHash, err := tree.Commit(ctx, testNs, 1)
	require.NoError(err, "Commit")
	root := node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}

	// Create a file-based checkpoint creator.
	fc, err := NewFileCreatorV1(filepath.Join(dir, "checkpoints"), ndb)
	require.NoError(err, "NewFileCreator")

	// There should be no checkpoints before one is created.
	cps, err := fc.GetCheckpoints(ctx, &GetCheckpointsRequest{})
	require.NoError(err, "GetCheckpoints")
	require.Len(cps, 0)

	_, err = fc.GetCheckpoint(ctx, 1, root)
	require.Error(err, "GetCheckpoint should fail with non-existent checkpoint")

	// Create a checkpoint and check that it has been created correctly.
	cp, err := fc.CreateCheckpoint(ctx, root, 16*1024)
	require.NoError(err, "CreateCheckpoint")
	require.EqualValues(1, cp.Version, "version should be correct")
	require.EqualValues(root, cp.Root, "checkpoint root should be correct")
	require.Len(cp.Chunks, 2, "there should be the correct number of chunks")

	var expectedChunks []hash.Hash
	for _, hh := range []string{
		"bd09a699c0737d8a9783129f896fb6f452d9b77e81869237312e3bd48fb4cbc7",
		"e852d2312ab1fe51ab066cc8a7a687e483d9e73206c3e56fc5caaecf6c347c7f",
	} {
		var h hash.Hash
		_ = h.UnmarshalHex(hh)
		expectedChunks = append(expectedChunks, h)
	}
	require.EqualValues(expectedChunks, cp.Chunks, "chunk hashes should be correct")

	// There should now be one checkpoint.
	cps, err = fc.GetCheckpoints(ctx, &GetCheckpointsRequest{Version: 1})
	require.NoError(err, "GetCheckpoints")
	require.Len(cps, 1, "there should be one checkpoint")
	require.Equal(cp, cps[0], "checkpoint returned by GetCheckpoint should be correct")

	gcp, err := fc.GetCheckpoint(ctx, 1, root)
	require.NoError(err, "GetCheckpoint")
	require.Equal(cp, gcp)

	// Try re-creating the same checkpoint again and make sure we get the same metadata.
	existingCp, err := fc.CreateCheckpoint(ctx, root, 16*1024)
	require.NoError(err, "CreateCheckpoint on an existing root should work")
	require.Equal(cp, existingCp, "created checkpoint should be correct")

	// We should be able to retrieve chunks.
	_, err = cp.GetChunkMetadata(999)
	require.Error(err, "GetChunkMetadata should fail for unknown chunk")
	chunk0, err := cp.GetChunkMetadata(0)
	require.NoError(err, "GetChunkMetadata")

	var buf bytes.Buffer
	err = fc.GetCheckpointChunk(ctx, chunk0, &buf)
	require.NoError(err, "GetChunk should work")

	// Fetching a non-existent chunk should fail.
	invalidChunk := *chunk0
	invalidChunk.Index = 999
	err = fc.GetCheckpointChunk(ctx, &invalidChunk, &buf)
	require.Error(err, "GetChunk on a non-existent chunk should fail")

	// Create a fresh node database to restore into.
	ndb2, err := factory.New(&dbApi.Config{
		DB:           filepath.Join(dir, "db2"),
		Namespace:    testNs,
		MaxCacheSize: 16 * 1024 * 1024,
	})
	require.NoError(err, "New")

	// Try to restore some chunks.
	rs, err := NewRestorer(ndb2)
	require.NoError(err, "NewRestorer")

	_, err = rs.RestoreChunk(ctx, 0, &buf)
	require.Error(err, "RestoreChunk should fail when no restore is in progress")
	require.True(errors.Is(err, ErrNoRestoreInProgress))

	// Generate a bogus manifest which does not verify by corrupting chunk at index 1.
	bogusCp, err := fc.GetCheckpoint(ctx, 1, root)
	require.NoError(err, "GetCheckpoint")
	require.Equal(cp, bogusCp)

	buf.Reset()
	sw := snappy.NewBufferedWriter(&buf)
	enc := cbor.NewEncoder(sw)
	_ = enc.Encode([]byte("this chunk is bogus"))
	sw.Close()

	bogusChunk := make([]byte, buf.Len())
	copy(bogusChunk, buf.Bytes())
	// Make sure that the chunk integrity is correct.
	bogusCp.Chunks[1].FromBytes(bogusChunk)

	err = ndb2.StartMultipartInsert(bogusCp.Root.Version)
	require.NoError(err, "StartMultipartInsert")
	err = rs.StartRestore(ctx, bogusCp)
	require.NoError(err, "StartRestore")
	for i := 0; i < len(bogusCp.Chunks); i++ {
		var cm *ChunkMetadata
		cm, err = cp.GetChunkMetadata(uint64(i))
		require.NoError(err, "GetChunkMetadata")

		buf.Reset()
		if i == 1 {
			// Substitute the bogus chunk.
			_, _ = buf.Write(bogusChunk)
		} else {
			err = fc.GetCheckpointChunk(ctx, cm, &buf)
			require.NoError(err, "GetChunk")
		}
		var done bool
		done, err = rs.RestoreChunk(ctx, uint64(i), &buf)
		require.False(done, "RestoreChunk should not signal completed restoration")
		if i == 1 {
			require.Error(err, "RestoreChunk should fail with bogus chunk")
			require.True(errors.Is(err, ErrChunkProofVerificationFailed))
			// Restorer should be reset.
			break
		}

		require.NoError(err, "RestoreChunk")
	}

	// Try to correctly restore.
	err = rs.StartRestore(ctx, cp)
	require.NoError(err, "StartRestore")
	err = rs.StartRestore(ctx, cp)
	require.Error(err, "StartRestore should fail when a restore is already in progress")
	require.True(errors.Is(err, ErrRestoreAlreadyInProgress))
	rcp := rs.GetCurrentCheckpoint()
	require.EqualValues(rcp, cp, "GetCurrentCheckpoint should return the checkpoint being restored")
	require.NotSame(rcp, cp, "GetCurrentCheckpoint should return a copy")
	for i := 0; i < len(cp.Chunks); i++ {
		var cm *ChunkMetadata
		cm, err = cp.GetChunkMetadata(uint64(i))
		require.NoError(err, "GetChunkMetadata")

		// Try with a corrupted chunk first.
		buf.Reset()
		_, _ = buf.Write([]byte("corrupted chunk"))
		_, err = rs.RestoreChunk(ctx, uint64(i), &buf)
		require.Error(err, "RestoreChunk should fail with corrupted chunk")

		buf.Reset()
		err = fc.GetCheckpointChunk(ctx, cm, &buf)
		require.NoError(err, "GetChunk")

		var done bool
		done, err = rs.RestoreChunk(ctx, uint64(i), &buf)
		require.NoError(err, "RestoreChunk")

		if i == len(cp.Chunks)-1 {
			require.True(done, "RestoreChunk should signal completed restoration when done")
		} else {
			require.False(done, "RestoreChunk should not signal completed restoration early")

			_, err = rs.RestoreChunk(ctx, uint64(i), &buf)
			require.Error(err, "RestoreChunk should fail if the same chunk has already been restored")
			require.True(errors.Is(err, ErrChunkAlreadyRestored))
		}
	}
	err = ndb2.Finalize([]node.Root{root})
	require.NoError(err, "Finalize")

	// Verify that everything has been restored.
	tree = mkvs.NewWithRoot(nil, ndb2, root)
	for i := 0; i < 1000; i++ {
		var value []byte
		value, err = tree.Get(ctx, []byte(strconv.Itoa(i)))
		require.NoError(err, "Get(%d)", i)
		require.Equal([]byte(strconv.Itoa(i)), value)
	}

	// Deleting a checkpoint should work.
	err = fc.DeleteCheckpoint(ctx, 1, root)
	require.NoError(err, "DeleteCheckpoint")

	// There should now be no checkpoints.
	cps, err = fc.GetCheckpoints(ctx, &GetCheckpointsRequest{Version: 1})
	require.NoError(err, "GetCheckpoints")
	require.Len(cps, 0, "there should be no checkpoints")

	// Make sure there are no empty directories.
	_, err = os.Stat(filepath.Join(dir, "checkpoints", strconv.FormatUint(root.Version, 10)))
	require.True(os.IsNotExist(err), "there should be no empty directories after deletion")

	_, err = fc.GetCheckpoint(ctx, 1, root)
	require.Error(err, "GetCheckpoint should fail with non-existent checkpoint")

	// Deleting a non-existent checkpoint should fail.
	err = fc.DeleteCheckpoint(ctx, 1, root)
	require.Error(err, "DeleteCheckpoint on a non-existent checkpoint should fail")

	// Fetching a non-existent chunk should fail.
	err = fc.GetCheckpointChunk(ctx, chunk0, &buf)
	require.Error(err, "GetChunk on a non-existent chunk should fail")

	// Create a checkpoint with unknown root.
	invalidRoot := root
	invalidRoot.Hash.FromBytes([]byte("mkvs checkpoint test invalid root"))
	_, err = fc.CreateCheckpoint(ctx, invalidRoot, 16*1024)
	require.Error(err, "CreateCheckpoint should fail for invalid root")
}

func TestOversizedChunks(t *testing.T) {
	dbTesting.TestMultipleBackends(t, db.Backends, testOversizedChunks)
}

func testOversizedChunks(t *testing.T, factory dbApi.Factory) {
	require := require.New(t)

	// Generate some data.
	dir, err := os.MkdirTemp("", "mkvs.checkpoint")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	ndb, err := factory.New(&dbApi.Config{
		DB:           filepath.Join(dir, "db"),
		Namespace:    testNs,
		MaxCacheSize: 16 * 1024 * 1024,
	})
	require.NoError(err, "New")

	ctx := context.Background()
	tree := mkvs.New(nil, ndb, node.RootTypeState)
	for i := 0; i < 100; i++ {
		err = tree.Insert(ctx,
			[]byte(fmt.Sprintf("this is some key at index %d which is somewhat longish", i)),
			[]byte(fmt.Sprintf("let's generate a somewhat long key at %d so that we try to overflow chunks", i)),
		)
		require.NoError(err, "Insert")
	}

	_, rootHash, err := tree.Commit(ctx, testNs, 1)
	require.NoError(err, "Commit")
	root := node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}

	// Create a file-based checkpoint creator.
	fc, err := NewFileCreatorV1(filepath.Join(dir, "checkpoints"), ndb)
	require.NoError(err, "NewFileCreator")

	// Create a checkpoint and check that it has been created correctly.
	cp, err := fc.CreateCheckpoint(ctx, root, 128)
	require.NoError(err, "CreateCheckpoint")
	require.EqualValues(1, cp.Version, "version should be correct")
	require.EqualValues(root, cp.Root, "checkpoint root should be correct")
	require.Len(cp.Chunks, 100, "there should be the correct number of chunks")
}

func TestPruneGapAfterCheckpointRestore(t *testing.T) {
	dbTesting.TestMultipleBackends(t, db.Backends, testPruneGapAfterCheckpointRestore)
}

func testPruneGapAfterCheckpointRestore(t *testing.T, factory dbApi.Factory) {
	require := require.New(t)

	// Generate some data.
	dir, err := os.MkdirTemp("", "mkvs.checkpoint")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	// Create two databases, the first will contain everything while the second one will only
	// contain the first few versions.
	ndb1, err := factory.New(&dbApi.Config{
		DB:        filepath.Join(dir, "db1"),
		Namespace: testNs,
	})
	require.NoError(err, "New")

	ndb2, err := factory.New(&dbApi.Config{
		DB:        filepath.Join(dir, "db2"),
		Namespace: testNs,
	})
	require.NoError(err, "New")

	ctx := context.Background()
	root := node.Root{
		Namespace: testNs,
		Version:   0,
		Type:      node.RootTypeState,
	}
	root.Hash.Empty()

	const (
		numVersions       = 20
		numKeysPerVersion = 50
		numVersionsDb2    = 5
		numExtraVersions  = 5
	)

	for v := uint64(0); v < numVersions; v++ {
		tree1 := mkvs.NewWithRoot(nil, ndb1, root)
		var tree2 mkvs.Tree
		if v < numVersionsDb2 {
			tree2 = mkvs.NewWithRoot(nil, ndb2, root)
		}

		for i := 0; i < numKeysPerVersion; i++ {
			err = tree1.Insert(ctx, []byte(strconv.Itoa(int(v)*1000+i)), []byte(strconv.Itoa(i)))
			require.NoError(err, "Insert")

			if tree2 != nil {
				err = tree2.Insert(ctx, []byte(strconv.Itoa(int(v)*1000+i)), []byte(strconv.Itoa(i)))
				require.NoError(err, "Insert")
			}
		}

		var rootHash1 hash.Hash
		_, rootHash1, err = tree1.Commit(ctx, testNs, v)
		require.NoError(err, "Commit")
		root1 := node.Root{
			Namespace: testNs,
			Version:   v,
			Type:      node.RootTypeState,
			Hash:      rootHash1,
		}
		err = ndb1.Finalize([]node.Root{root1})
		require.NoError(err, "Finalize")
		tree1.Close()

		if tree2 != nil {
			var rootHash2 hash.Hash
			_, rootHash2, err = tree2.Commit(ctx, testNs, v)
			require.NoError(err, "Commit")
			require.EqualValues(rootHash1, rootHash2, "root hashes should be equal")
			root2 := node.Root{
				Namespace: testNs,
				Version:   v,
				Type:      node.RootTypeState,
				Hash:      rootHash2,
			}
			err = ndb2.Finalize([]node.Root{root2})
			require.NoError(err, "Finalize")
			tree2.Close()
		}

		root.Version = v
		root.Hash = rootHash1
	}

	// Create a file-based checkpoint creator for the first database.
	fc, err := NewFileCreatorV1(filepath.Join(dir, "checkpoints"), ndb1)
	require.NoError(err, "NewFileCreator")

	// Create a checkpoint and check that it has been created correctly.
	cp, err := fc.CreateCheckpoint(ctx, root, 16*1024)
	require.NoError(err, "CreateCheckpoint")

	// Restore checkpoints in the second database.
	rs, err := NewRestorer(ndb2)
	require.NoError(err, "NewRestorer")

	err = ndb2.StartMultipartInsert(cp.Root.Version)
	require.NoError(err, "StartMultipartInsert")
	err = rs.StartRestore(ctx, cp)
	require.NoError(err, "StartRestore")
	for i := 0; i < len(cp.Chunks); i++ {
		var cm *ChunkMetadata
		cm, err = cp.GetChunkMetadata(uint64(i))
		require.NoError(err, "GetChunkMetadata")

		var buf bytes.Buffer
		err = fc.GetCheckpointChunk(ctx, cm, &buf)
		require.NoError(err, "GetChunk")

		_, err = rs.RestoreChunk(ctx, uint64(i), &buf)
		require.NoError(err, "RestoreChunk")
	}
	err = ndb2.Finalize([]node.Root{root})
	require.NoError(err, "Finalize")

	// Now attempt to prune everything up to (but excluding) the current root.
	for v := uint64(0); v < root.Version; v++ {
		err = ndb2.Prune(v)
		require.NoError(err, "Prune(%d)", v)
	}
	checkpointRootVersion := root.Version

	// Insert some more stuff in the node database to make sure everything still works.
	finalVersion := root.Version + numExtraVersions
	for v := root.Version + 1; v <= finalVersion; v++ {
		tree1 := mkvs.NewWithRoot(nil, ndb1, root)
		tree2 := mkvs.NewWithRoot(nil, ndb2, root)

		for i := 0; i < numKeysPerVersion; i++ {
			err = tree1.Insert(ctx, []byte(strconv.Itoa(int(v)*1000+i)), []byte(strconv.Itoa(i)))
			require.NoError(err, "Insert")
			err = tree2.Insert(ctx, []byte(strconv.Itoa(int(v)*1000+i)), []byte(strconv.Itoa(i)))
			require.NoError(err, "Insert")
		}

		var rootHash1 hash.Hash
		_, rootHash1, err = tree1.Commit(ctx, testNs, v)
		require.NoError(err, "Commit")
		root1 := node.Root{
			Namespace: testNs,
			Version:   v,
			Type:      node.RootTypeState,
			Hash:      rootHash1,
		}
		err = ndb1.Finalize([]node.Root{root1})
		require.NoError(err, "Finalize")
		tree1.Close()

		var rootHash2 hash.Hash
		_, rootHash2, err = tree2.Commit(ctx, testNs, v)
		require.NoError(err, "Commit")
		require.EqualValues(rootHash1, rootHash2, "root hashes should be equal")
		root2 := node.Root{
			Namespace: testNs,
			Version:   v,
			Type:      node.RootTypeState,
			Hash:      rootHash2,
		}
		err = ndb2.Finalize([]node.Root{root2})
		require.NoError(err, "Finalize")
		tree2.Close()

		root.Version = v
		root.Hash = rootHash1
	}

	// Prune the checkpoint root version.
	err = ndb2.Prune(checkpointRootVersion)
	require.NoError(err, "Prune(%d)", checkpointRootVersion)
}

// TODO:
//   - Unify style
//   - Make helpers reusable for other tests.
//   - Fuzz both backends.
func FuzzCheckpointCreation(f *testing.F) {
	f.Fuzz(func(t *testing.T, seed int64, n uint16, depth uint8, chunkSize uint64) {
		if chunkSize == 0 { // TODO check why this condition is not needed.
			t.Skip("skipping zero chunk size")
		}
		ctx := context.Background()
		dir, err := os.MkdirTemp("", "mkvs.Checkpoint")
		if err != nil {
			t.Fatalf("failed to create new temporary dir: %v", err)
		}
		defer os.RemoveAll(dir)

		// Create node database.
		cfg1 := &dbApi.Config{
			DB:           filepath.Join(dir, "db1"),
			Namespace:    testNs,
			MaxCacheSize: 16 * 1024 * 1024,
		}
		ndb1, err := pathbadger.New(cfg1)
		if err != nil {
			t.Fatalf("failed to create new pathbadger backend: %v", err)
		}
		defer ndb1.Close()

		// Populate node database with random entries.
		tree1 := mkvs.New(nil, ndb1, node.RootTypeState)
		defer tree1.Close()
		root := populateDb(ctx, t, tree1, testNs, n, seed)
		err = ndb1.Finalize([]node.Root{root})
		if err != nil {
			t.Fatalf("Failed to finalized ndb1")
		}

		// Create a checkpoint.
		fc, err := NewFileCreatorV2(filepath.Join(dir, "checkpoints"), ndb1)
		if err != nil {
			t.Fatalf("failed to create new checkpoint creator: %v", err)
		}
		cp, err := fc.CreateCheckpoint(ctx, root, chunkSize)
		if err != nil {
			t.Fatalf("creating checkpoint (rootHash: %.8s, chunkSize: %d): %v", root.Hash, chunkSize, err)
		}

		// Create a fresh node database.
		cfg2 := &dbApi.Config{
			DB:           filepath.Join(dir, "db2"),
			Namespace:    testNs,
			MaxCacheSize: 16 * 1024 * 1024,
		}
		ndb2, err := pathbadger.New(cfg2)
		if err != nil {
			t.Fatalf("failed to create new pathbadger backend: %v", err)
		}
		defer ndb2.Close()

		// Restore checkpoints into the second database.
		restoreCheckpoint(ctx, t, ndb2, cp, fc, root)

		// Iterate over keyset of both databases and ensure equal entries.
		tree2 := mkvs.NewWithRoot(nil, ndb2, root)
		defer tree2.Close()
		it1 := tree1.NewIterator(ctx)
		defer it1.Close()
		it2 := tree2.NewIterator(ctx)
		defer it2.Close()
		it1.Rewind()
		it2.Rewind()
		for ; it1.Valid(); it1.Next() {
			if !it2.Valid() {
				t.Error("Key missing in the second database")
			}
			key1 := it1.Key()
			key2 := it2.Key()
			if !bytes.Equal(key1, key2) {
				t.Fatalf("Keys not equal: want %s, got %s", key1, key2)
			}
			val1 := it1.Key()
			val2 := it2.Key()
			if !bytes.Equal(val1, val2) {
				t.Fatalf("Values not equal: want %s, got %s", val1, val2)
			}
			it2.Next()
		}

	})
}

// TODO it would be nice to create general purpose Db initiliazer for tests, with
// various properties (e.g. seq numbers as keys, random byte keys, etc)
// We could reuse this logic in many places.
func populateDb(ctx context.Context, t *testing.T, tree mkvs.Tree, ns common.Namespace, n uint16, seed int64) node.Root {
	t.Helper()

	rnd := rand.New(rand.NewSource(seed))

	for i := 0; i < int(n); i++ {
		key := make([]byte, rnd.Intn(10)) // TODO Set limit to node.Key max size.
		val := make([]byte, rnd.Intn(10))

		if _, err := rnd.Read(key); err != nil {
			t.Fatalf("failed to create random key")
		}
		if _, err := rnd.Read(val); err != nil {
			t.Fatalf("failed to create random value")
		}

		if err := tree.Insert(ctx, key, val); err != nil {
			t.Fatalf("Insert(%x, %x): %v", key, val, err)
		}
	}

	version := 1
	_, rootHash, err := tree.Commit(ctx, ns, uint64(version))
	if err != nil {
		t.Fatalf("Commit(%.8s, %d): %v", ns, version, err)
	}

	return node.Root{
		Namespace: ns,
		Version:   uint64(version),
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}

}

func TestCheckpointCreationRestoration(t *testing.T) {
	ndb1 := getSapphireMainnetNodeDB(t)
	defer ndb1.Close()

	root := getLatestStateRoot(t, ndb1)

	targetDir := os.Getenv("TARGET_DIR")
	targetDir = filepath.Join(targetDir, "sapphire_mainnet", strconv.Itoa(int(root.Version)))
	if err := os.MkdirAll(targetDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	// Create a checkpoint.
	// start := time.Now()
	// fmt.Println(filepath.Join(targetDir, "checkpoints"))
	// fc, err := NewFileCreatorV2(filepath.Join(targetDir, "checkpoints"), ndb1)
	// if err != nil {
	// 	t.Fatalf("Creating new checkpoint creator: %v", err)
	// }

	// var chunkSize uint64 = 8 * 1024 * 1024
	// cp, err := fc.CreateCheckpoint(context.Background(), root, chunkSize)
	// if err != nil {
	// 	t.Fatalf("Creating checkpoint: %v", err)
	// }
	// fmt.Printf("Creating checkpoint took %.2f min", time.Since(start).Minutes())

	// Create a fresh node database.
	cfg2 := &dbApi.Config{
		DB:           filepath.Join(targetDir, "db2"),
		Namespace:    root.Namespace,
		MaxCacheSize: 16 * 1024 * 1024,
	}
	ndb2, err := pathbadger.New(cfg2)
	if err != nil {
		t.Fatalf("failed to create new pathbadger backend: %v", err)
	}
	defer ndb2.Close()

	fmt.Println(cfg2.DB)

	// v, ok := ndb2.GetLatestVersion()
	// if !ok {
	// 	t.Fatalf("Empty nodedb")
	// }
	// fmt.Println(v)

	// // Restore checkpoints into the second database.
	// start = time.Now()
	// restoreCheckpoint(context.Background(), t, ndb2, cp, fc, root)
	// fmt.Printf("Restoring checkpoint took %.2f min", time.Since(start).Minutes())

	// //

	// fmt.Println(root)
	// fmt.Println(ndb1.GetRootsForVersion(v))
	tree1 := mkvs.NewWithRoot(nil, ndb1, root)
	defer tree1.Close()
	tree2 := mkvs.NewWithRoot(nil, ndb2, root)
	defer tree2.Close()
	iter1 := tree1.NewIterator(context.Background())
	defer iter1.Close()
	iter2 := tree2.NewIterator(context.Background())
	defer iter2.Close()

	iter2.Rewind()

	var iterated int
	for iter1.Rewind(); iter1.Valid(); iter1.Next() {
		iterated++
		if !iter2.Valid() {
			fmt.Println(iter1.Key())
			t.Fatalf("Missing key %d", iterated)
		}
		key1, key2 := iter1.Key(), iter2.Key()
		val1, val2 := iter1.Value(), iter2.Value()

		if !key1.Equal(key2) {
			t.Fatalf("Keys not equal: got %s, want %s", key1, key2)
		}

		if !bytes.Equal(val1, val2) {
			t.Fatalf("Keys not equal: got %v, want %v", val1, val2)
		}

		iter2.Next()
	}
	fmt.Println(iter1.Key())

}

func restoreCheckpoint(ctx context.Context, t *testing.T, ndb2 dbApi.NodeDB, cp *Metadata, fc Creator, root node.Root) {
	rs, err := NewRestorer(ndb2)
	if err != nil {
		t.Fatalf("NewRestorer(ndb2): %v", err)
	}
	if err = ndb2.StartMultipartInsert(cp.Root.Version); err != nil {
		t.Fatalf("StartMultipartInsert(%d): %v", cp.Root.Version, err)
	}

	if err = rs.StartRestore(ctx, cp); err != nil {
		t.Fatalf("StartRestore: %v", err)
	}

	for i := 0; i < len(cp.Chunks); i++ {
		var cm *ChunkMetadata
		cm, err = cp.GetChunkMetadata(uint64(i))
		if err != nil {
			t.Fatalf("GetChunkMetadata(%d): %v", i, err)
		}
		var buf bytes.Buffer
		if err = fc.GetCheckpointChunk(ctx, cm, &buf); err != nil {
			t.Fatalf("GetCheckpointChunk: %s", err)
		}
		if _, err = rs.RestoreChunk(ctx, uint64(i), &buf); err != nil {
			t.Fatalf("RestoreChunk: %v", err)
		}
	}

	if err = ndb2.Finalize([]node.Root{root}); err != nil {
		t.Fatalf("Finalize: %v", err)
	}

}

func TestMeasureKeysSize(t *testing.T) {
	ndb := getSapphireMainnetNodeDB(t)
	defer ndb.Close()

	root := getLatestStateRoot(t, ndb)
	tree := mkvs.NewWithRoot(nil, ndb, root)
	defer tree.Close()

	it := tree.NewIterator(context.Background())
	defer it.Close()

	start := time.Now()
	var keys, keysSize, valsSize uint64
	for it.Rewind(); it.Valid(); it.Next() {
		keys++
		keysSize += uint64(len(it.Key()))
		valsSize += uint64(len(it.Value()))
	}

	fmt.Printf("Keys: %d, keys size: %d, vals size: %d\n", keys, keysSize, valsSize)
	fmt.Println(time.Since(start).Minutes())
}

func getSapphireMainnetNodeDB(t *testing.T) dbApi.NodeDB {
	t.Helper()

	var ns common.Namespace
	ns.UnmarshalHex("000000000000000000000000000000000000000000000000f80306c9858e7279")
	nodedbDir := os.Getenv("NODEDB_DIR")

	cfg := &dbApi.Config{
		DB:           nodedbDir,
		Namespace:    ns,
		MaxCacheSize: 16 * 1024 * 1024,
	}
	ndb, err := pathbadger.New(cfg)
	if err != nil {
		t.Fatalf("Creating new pathbadger backend: %v", err)
	}
	return ndb
}

func getLatestStateRoot(t *testing.T, ndb dbApi.NodeDB) node.Root {
	t.Helper()
	version, ok := ndb.GetLatestVersion()
	if !ok {
		t.Fatalf("Empty nodedb")
	}

	fmt.Printf("version: %d\n", version)

	roots, err := ndb.GetRootsForVersion(version)
	if err != nil {
		t.Fatalf("ndb.GetRootsForVersion(%d): %v", version, err)
	}

	root := roots[0]
	if root.Type != node.RootTypeState {
		t.Fatalf("Expected state root type")
	}

	return root
}
