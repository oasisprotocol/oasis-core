package checkpoint_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	badgerDb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pebbledb"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

type NodeDBFactory func(cfg *db.Config) (db.NodeDB, error)

var testNs = common.NewTestNamespaceFromSeed([]byte("oasis mkvs checkpoint test ns"), 0)

func TestBadgerBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (NodeDBFactory, func()) {
		// Create a new random temporary directory under /tmp.
		dir, err := os.MkdirTemp("", "mkvs.checkpoint_test.badger")
		require.NoError(t, err, "TempDir")

		// Create a Badger-backed Node DB factory.
		factory := func(cfg *db.Config) (db.NodeDB, error) {
			return badgerDb.New(cfg)
		}

		cleanup := func() {
			os.RemoveAll(dir)
		}

		return factory, cleanup
	}, nil)
}

func TestPebbledbBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (NodeDBFactory, func()) {
		// Create a new random temporary directory under /tmp.
		dir, err := os.MkdirTemp("", "mkvs.checkpoint_test.pebbledb")
		require.NoError(t, err, "TempDir")

		// Create a Badger-backed Node DB factory.
		factory := func(cfg *db.Config) (db.NodeDB, error) {
			return pebbledb.New(cfg)
		}

		cleanup := func() {
			os.RemoveAll(dir)
		}

		return factory, cleanup
	}, nil)
}

func testBackend(
	t *testing.T,
	initBackend func(t *testing.T) (NodeDBFactory, func()),
	skipTests []string,
) {
	tests := []struct {
		name string
		fn   func(*testing.T, NodeDBFactory)
	}{
		{"FileCheckpointCreator", testFileCheckpointCreator},
		{"OversizedChunks", testOversizedChunks},
		{"PruneGapAfterCheckpointRestore", testPruneGapAfterCheckpointRestore},
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
			defer cleanup()
			tc.fn(t, factory)
		})
	}
}

func testFileCheckpointCreator(t *testing.T, new NodeDBFactory) {
	require := require.New(t)

	// Generate some data.
	dir, err := os.MkdirTemp("", "mkvs.checkpoint")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	ndb, err := new(&db.Config{
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

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(err, "Commit")
	root := node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}

	// Create a file-based checkpoint creator.
	fc, err := checkpoint.NewFileCreator(filepath.Join(dir, "checkpoints"), ndb)
	require.NoError(err, "NewFileCreator")

	// There should be no checkpoints before one is created.
	cps, err := fc.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{})
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
	cps, err = fc.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1})
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
	ndb2, err := new(&db.Config{
		DB:           filepath.Join(dir, "db2"),
		Namespace:    testNs,
		MaxCacheSize: 16 * 1024 * 1024,
	})
	require.NoError(err, "New")

	// Try to restore some chunks.
	rs, err := checkpoint.NewRestorer(ndb2)
	require.NoError(err, "NewRestorer")

	_, err = rs.RestoreChunk(ctx, 0, &buf)
	require.Error(err, "RestoreChunk should fail when no restore is in progress")
	require.True(errors.Is(err, checkpoint.ErrNoRestoreInProgress))

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
		var cm *checkpoint.ChunkMetadata
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
			require.True(errors.Is(err, checkpoint.ErrChunkProofVerificationFailed))
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
	require.True(errors.Is(err, checkpoint.ErrRestoreAlreadyInProgress))
	rcp := rs.GetCurrentCheckpoint()
	require.EqualValues(rcp, cp, "GetCurrentCheckpoint should return the checkpoint being restored")
	require.NotSame(rcp, cp, "GetCurrentCheckpoint should return a copy")
	for i := 0; i < len(cp.Chunks); i++ {
		var cm *checkpoint.ChunkMetadata
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
			require.True(errors.Is(err, checkpoint.ErrChunkAlreadyRestored))
		}
	}
	err = ndb2.Finalize([]node.Root{root})
	require.NoError(err, "Finalize")

	// Verify that everything has been restored.
	tree = mkvs.NewWithRoot(nil, ndb2, root)
	for i := 0; i < 1000; i++ {
		var value []byte
		value, err = tree.Get(ctx, []byte(strconv.Itoa(i)))
		require.NoError(err, "Get")
		require.Equal([]byte(strconv.Itoa(i)), value)
	}

	// Deleting a checkpoint should work.
	err = fc.DeleteCheckpoint(ctx, 1, root)
	require.NoError(err, "DeleteCheckpoint")

	// There should now be no checkpoints.
	cps, err = fc.GetCheckpoints(ctx, &checkpoint.GetCheckpointsRequest{Version: 1})
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

func testOversizedChunks(t *testing.T, new NodeDBFactory) {
	require := require.New(t)

	// Generate some data.
	dir, err := os.MkdirTemp("", "mkvs.checkpoint")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	ndb, err := new(&db.Config{
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

	_, rootHash, err := tree.Commit(ctx, testNs, 0)
	require.NoError(err, "Commit")
	root := node.Root{
		Namespace: testNs,
		Version:   1,
		Type:      node.RootTypeState,
		Hash:      rootHash,
	}

	// Create a file-based checkpoint creator.
	fc, err := checkpoint.NewFileCreator(filepath.Join(dir, "checkpoints"), ndb)
	require.NoError(err, "NewFileCreator")

	// Create a checkpoint and check that it has been created correctly.
	cp, err := fc.CreateCheckpoint(ctx, root, 128)
	require.NoError(err, "CreateCheckpoint")
	require.EqualValues(1, cp.Version, "version should be correct")
	require.EqualValues(root, cp.Root, "checkpoint root should be correct")
	require.Len(cp.Chunks, 100, "there should be the correct number of chunks")
}

func testPruneGapAfterCheckpointRestore(t *testing.T, new NodeDBFactory) {
	require := require.New(t)

	// Generate some data.
	dir, err := os.MkdirTemp("", "mkvs.checkpoint")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	// Create two databases, the first will contain everything while the second one will only
	// contain the first few versions.
	ndb1, err := new(&db.Config{
		DB:        filepath.Join(dir, "db1"),
		Namespace: testNs,
	})
	require.NoError(err, "New")

	ndb2, err := new(&db.Config{
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
	fc, err := checkpoint.NewFileCreator(filepath.Join(dir, "checkpoints"), ndb1)
	require.NoError(err, "NewFileCreator")

	// Create a checkpoint and check that it has been created correctly.
	cp, err := fc.CreateCheckpoint(ctx, root, 16*1024)
	require.NoError(err, "CreateCheckpoint")

	// Restore checkpoints in the second database.
	rs, err := checkpoint.NewRestorer(ndb2)
	require.NoError(err, "NewRestorer")

	err = ndb2.StartMultipartInsert(cp.Root.Version)
	require.NoError(err, "StartMultipartInsert")
	err = rs.StartRestore(ctx, cp)
	require.NoError(err, "StartRestore")
	for i := 0; i < len(cp.Chunks); i++ {
		var cm *checkpoint.ChunkMetadata
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
		err = ndb2.Prune(ctx, v)
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
	err = ndb2.Prune(ctx, checkpointRootVersion)
	require.NoError(err, "Prune(%d)", checkpointRootVersion)
}
