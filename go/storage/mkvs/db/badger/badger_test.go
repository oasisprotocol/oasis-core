package badger

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/dgraph-io/badger/v2"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

var (
	nodePrefix = nodeKeyFmt.Encode()

	logPrefix = multipartRestoreNodeLogKeyFmt.Encode()

	testNs = common.NewTestNamespaceFromSeed([]byte("badger node db test ns"), 0)

	dbCfg = &api.Config{
		Namespace:    testNs,
		MaxCacheSize: 16 * 1024 * 1024,
		NoFsync:      true,
		MemoryOnly:   true,
	}

	testValues = [][]byte{
		[]byte("colorless green ideas sleep furiously"),
		[]byte("excepting understandable chairs piously"),
		[]byte("at the prickle for rainbow hoovering"),
	}
)

type keySet map[string]struct{}

type test struct {
	require  *require.Assertions
	ctx      context.Context
	dir      string
	badgerdb *badgerNodeDB
	ckMeta   *checkpoint.Metadata
	ckNodes  keySet
}

func fillDB(ctx context.Context, require *require.Assertions, values [][]byte, version uint64, ndb api.NodeDB) node.Root {
	emptyRoot := node.Root{
		Namespace: testNs,
		Version:   version,
		Type:      node.RootTypeState,
	}
	emptyRoot.Hash.Empty()

	tree := mkvs.NewWithRoot(nil, ndb, emptyRoot)
	require.NotNil(tree, "NewWithRoot()")

	var wl writelog.WriteLog
	for i, val := range values {
		wl = append(wl, writelog.LogEntry{Key: []byte(strconv.Itoa(i)), Value: val})
	}

	err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(wl))
	require.NoError(err, "ApplyWriteLog()")

	_, hash, err := tree.Commit(ctx, testNs, 2)
	require.NoError(err, "Commit()")

	return node.Root{
		Namespace: testNs,
		Version:   version + 1,
		Type:      node.RootTypeState,
		Hash:      hash,
	}
}

func createCheckpoint(ctx context.Context, require *require.Assertions, dir string, values [][]byte, version uint64) (*checkpoint.Metadata, keySet) {
	ndb, err := New(dbCfg)
	require.NoError(err, "New()")
	defer ndb.Close()
	badgerdb := ndb.(*badgerNodeDB)
	fc, err := checkpoint.NewFileCreator(dir, ndb)
	require.NoError(err, "NewFileCreator()")

	ckRoot := fillDB(ctx, require, values, version, ndb)
	ckMeta, err := fc.CreateCheckpoint(ctx, ckRoot, 1024*1024)
	require.NoError(err, "CreateCheckpoint()")

	nodeKeys := keySet{}
	err = badgerdb.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			if bytes.HasPrefix(it.Item().Key(), nodePrefix) {
				nodeKeys[string(it.Item().Key())] = struct{}{}
			}
		}
		return nil
	})
	require.NoError(err, "createCheckpoint()")

	return ckMeta, nodeKeys
}

func verifyNodes(require *require.Assertions, badgerdb *badgerNodeDB, keySet keySet) {
	notVisited := map[string]struct{}{}
	for k := range keySet {
		notVisited[k] = struct{}{}
	}
	err := badgerdb.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().Key()
			if !bytes.HasPrefix(key, nodePrefix) {
				continue
			}
			_, ok := keySet[string(key)]
			require.Equal(true, ok, "unexpected node in db")
			delete(notVisited, string(key))
		}
		return nil
	})
	require.NoError(err, "verifyNodes()")
	require.Equal(0, len(notVisited), "some nodes not visited")
}

func checkNoLogKeys(require *require.Assertions, badgerdb *badgerNodeDB) {
	err := badgerdb.db.View(func(txn *badger.Txn) error {
		it := txn.NewIterator(badger.DefaultIteratorOptions)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			key := it.Item().Key()
			require.False(bytes.HasPrefix(key, logPrefix), "checkLogKeys()/iteration")
		}
		return nil
	})
	require.NoError(err, "checkNoLogKeys()")
}

func restoreCheckpoint(ctx *test, ckMeta *checkpoint.Metadata, ckNodes keySet) checkpoint.Restorer {
	fc, err := checkpoint.NewFileCreator(ctx.dir, ctx.badgerdb)
	ctx.require.NoError(err, "NewFileCreator() - 2")

	restorer, err := checkpoint.NewRestorer(ctx.badgerdb)
	ctx.require.NoError(err, "NewRestorer()")

	err = restorer.StartRestore(ctx.ctx, ckMeta)
	ctx.require.NoError(err, "StartRestore()")
	for i := range ckMeta.Chunks {
		idx := uint64(i)
		chunkMeta, err := ckMeta.GetChunkMetadata(idx)
		ctx.require.NoError(err, fmt.Sprintf("GetChunkMetadata(%d)", idx))
		func() {
			r, w, err := os.Pipe()
			ctx.require.NoError(err, "Pipe()")
			errCh := make(chan error)
			go func() {
				_, errr := restorer.RestoreChunk(ctx.ctx, idx, r)
				errCh <- errr
			}()
			err = fc.GetCheckpointChunk(ctx.ctx, chunkMeta, w)
			w.Close()
			errRestore := <-errCh
			ctx.require.NoError(err, "GetCheckpointChunk()")
			ctx.require.NoError(errRestore, "RestoreChunk()")
		}()
	}

	verifyNodes(ctx.require, ctx.badgerdb, ckNodes)

	return restorer
}

func TestMultipartRestore(t *testing.T) {
	ctx := context.Background()
	wrap := func(testFunc func(ctx *test), initialValues [][]byte) func(*testing.T) {
		return func(t *testing.T) {
			require := require.New(t)

			dir, err := ioutil.TempDir("", "oasis-storage-database-test")
			require.NoError(err, "TempDir()")
			defer os.RemoveAll(dir)

			ckMeta, ckNodes := createCheckpoint(ctx, require, dir, initialValues, 1)

			ndb, err := New(dbCfg)
			require.NoError(err, "New() - 2")
			defer ndb.Close()
			badgerdb := ndb.(*badgerNodeDB)

			testCtx := &test{
				require:  require,
				ctx:      ctx,
				dir:      dir,
				badgerdb: badgerdb,
				ckMeta:   ckMeta,
				ckNodes:  ckNodes,
			}
			testFunc(testCtx)
		}
	}

	t.Run("Abort", wrap(testAbort, testValues))
	t.Run("Finalize", wrap(testFinalize, testValues))
	t.Run("ExistingNodes", wrap(testExistingNodes, testValues[:1]))
}

func testAbort(ctx *test) {
	// Abort a restore, check nodes again.
	// There should be no leftover nodes, and the log keys should be gone too.
	restorer := restoreCheckpoint(ctx, ctx.ckMeta, ctx.ckNodes)
	err := restorer.AbortRestore(ctx.ctx)
	ctx.require.NoError(err, "AbortRestore()")

	verifyNodes(ctx.require, ctx.badgerdb, keySet{})
	checkNoLogKeys(ctx.require, ctx.badgerdb)
}

func testFinalize(ctx *test) {
	// Finalize a restore, check nodes again.
	// This time, all the restored nodes should be present, but the
	// log keys should be gone.
	restoreCheckpoint(ctx, ctx.ckMeta, ctx.ckNodes)

	// Test parameter sanity checking first.
	err := ctx.badgerdb.Finalize(ctx.ctx, nil)
	ctx.require.Error(err, "Finalize with no roots should fail")

	bogusRoot := ctx.ckMeta.Root
	bogusRoot.Version++
	err = ctx.badgerdb.Finalize(ctx.ctx, []node.Root{ctx.ckMeta.Root, bogusRoot})
	ctx.require.Error(err, "Finalize with roots from different versions should fail")

	err = ctx.badgerdb.Finalize(ctx.ctx, []node.Root{ctx.ckMeta.Root})
	ctx.require.NoError(err, "Finalize()")

	verifyNodes(ctx.require, ctx.badgerdb, ctx.ckNodes)
	checkNoLogKeys(ctx.require, ctx.badgerdb)
}

func testExistingNodes(ctx *test) {
	// Create two checkpoints, so we have two sets of nodes.
	// The first checkpoint will be the base for a fresh database and must include
	// a node from the second checkpoint, which will be used for multipart restore.
	// The pre-existing node should then not be deleted after aborting the second
	// checkpoint.

	// Create the checkpoint to be used as the overriding restore.
	ckMeta2, ckNodes2 := createCheckpoint(ctx.ctx, ctx.require, ctx.dir, testValues, 2)
	var overlap bool
	for node1 := range ctx.ckNodes {
		if _, ok := ckNodes2[node1]; ok {
			overlap = true
			break
		}
	}
	ctx.require.Equal(true, overlap, "pointless test when no nodes would overlap")

	// Restore first checkpoint. The database is empty.
	restoreCheckpoint(ctx, ctx.ckMeta, ctx.ckNodes)
	err := ctx.badgerdb.Finalize(ctx.ctx, []node.Root{ctx.ckMeta.Root})
	ctx.require.NoError(err, "Finalize()")
	verifyNodes(ctx.require, ctx.badgerdb, ctx.ckNodes)

	// Restore the second checkpoint. One of the nodes from it already exists. After aborting,
	// exactly the nodes from the first checkpoint should remain.
	restorer := restoreCheckpoint(ctx, ckMeta2, ckNodes2)
	err = restorer.AbortRestore(ctx.ctx)
	ctx.require.NoError(err, "AbortRestore()")
	verifyNodes(ctx.require, ctx.badgerdb, ctx.ckNodes)
}

func TestVersionChecks(t *testing.T) {
	require := require.New(t)
	ndb, err := New(dbCfg)
	require.NoError(err, "New()")
	defer ndb.Close()
	badgerdb := ndb.(*badgerNodeDB)

	err = badgerdb.StartMultipartInsert(0)
	require.Error(err, "StartMultipartInsert(0)")

	err = badgerdb.StartMultipartInsert(42)
	require.NoError(err, "StartMultipartInsert(42)")
	err = badgerdb.StartMultipartInsert(44)
	require.Error(err, "StartMultipartInsert(44)")

	root := node.Root{}
	_, err = badgerdb.NewBatch(root, 0, false) // Normal chunks not allowed during multipart.
	require.Error(err, "NewBatch(.., 0, false)")
	_, err = badgerdb.NewBatch(root, 13, true)
	require.Error(err, "NewBatch(.., 13, true)")
	batch, err := badgerdb.NewBatch(root, 42, true)
	require.NoError(err, "NewBatch(.., 42, true)")
	defer batch.Reset()

	err = batch.Commit(root)
	require.Error(err, "Commit(Root{0})")
}

func TestReadOnlyBatch(t *testing.T) {
	require := require.New(t)

	// No way to initialize a readonly-database, so it needs to be created rw first.
	// This means we need persistence.
	dir, err := ioutil.TempDir("", "oasis-storage-database-test")
	require.NoError(err, "TempDir()")
	defer os.RemoveAll(dir)

	readonlyCfg := *dbCfg
	readonlyCfg.MemoryOnly = false
	readonlyCfg.ReadOnly = false
	readonlyCfg.DB = dir

	func() {
		ndb, errRw := New(&readonlyCfg)
		require.NoError(errRw, "New() - 1")
		defer ndb.Close()
	}()

	readonlyCfg.ReadOnly = true
	ndb, err := New(&readonlyCfg)
	require.NoError(err, "New() - 2")
	defer ndb.Close()
	badgerdb := ndb.(*badgerNodeDB)

	_, err = badgerdb.NewBatch(node.Root{}, 13, false)
	require.Error(err, "NewBatch()")
}
