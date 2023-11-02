package rocksdb

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/linxGnu/grocksdb"
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

	testNs = common.NewTestNamespaceFromSeed([]byte("rocksdb node db test ns"), 0)

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
	require *require.Assertions
	ctx     context.Context
	dir     string
	rocksdb *rocksdbNodeDB
	ckMeta  *checkpoint.Metadata
	ckNodes keySet
}

func fillDB(
	ctx context.Context,
	require *require.Assertions,
	values [][]byte,
	prevRoot *node.Root,
	version, commitVersion uint64,
	ndb api.NodeDB,
) node.Root {
	if prevRoot == nil {
		emptyRoot := node.Root{
			Namespace: testNs,
			Version:   version,
			Type:      node.RootTypeState,
		}
		emptyRoot.Hash.Empty()
		prevRoot = &emptyRoot
	}

	tree := mkvs.NewWithRoot(nil, ndb, *prevRoot)
	require.NotNil(tree, "NewWithRoot()")

	var wl writelog.WriteLog
	for i, val := range values {
		wl = append(wl, writelog.LogEntry{Key: []byte(strconv.Itoa(i)), Value: val})
	}

	err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(wl))
	require.NoError(err, "ApplyWriteLog()")

	_, hash, err := tree.Commit(ctx, testNs, commitVersion)
	require.NoError(err, "Commit()")

	return node.Root{
		Namespace: testNs,
		Version:   version + 1,
		Type:      node.RootTypeState,
		Hash:      hash,
	}
}

func createCheckpoint(ctx context.Context, require *require.Assertions, dir string, values [][]byte, version uint64) (*checkpoint.Metadata, keySet) {
	dbDir, err := os.MkdirTemp(dir, "checkpoint-db")
	require.NoError(err, "TempDir()")
	dbCfg := *dbCfg
	dbCfg.DB = dbDir
	ndb, err := New(&dbCfg)
	require.NoError(err, "New()")
	defer ndb.Close()
	rocksdb := ndb.(*rocksdbNodeDB)
	fc, err := checkpoint.NewFileCreator(dir, ndb)
	require.NoError(err, "NewFileCreator()")

	ckRoot := fillDB(ctx, require, values, nil, version, 2, ndb)
	ckMeta, err := fc.CreateCheckpoint(ctx, ckRoot, 1024*1024)
	require.NoError(err, "CreateCheckpoint()")

	nodeKeys := keySet{}

	loadNodes := func(cf *grocksdb.ColumnFamilyHandle) {
		it := prefixIterator(rocksdb.db.NewIteratorCF(timestampReadOptions(2), cf), nil)
		defer it.Close()
		for ; it.Valid(); it.Next() {
			if bytes.HasPrefix(it.Key(), nodePrefix) {
				nodeKeys[string(it.Key())] = struct{}{}
			}
		}
	}
	loadNodes(rocksdb.cfIOTree)
	loadNodes(rocksdb.cfStateTree)

	return ckMeta, nodeKeys
}

func verifyNodes(require *require.Assertions, rocksdb *rocksdbNodeDB, version uint64, keySet keySet) {
	notVisited := map[string]struct{}{}
	for k := range keySet {
		notVisited[k] = struct{}{}
	}

	checkNodes := func(cf *grocksdb.ColumnFamilyHandle) {
		fmt.Println("checking nodes")
		it := prefixIterator(rocksdb.db.NewIteratorCF(timestampReadOptions(version), cf), nil)
		defer it.Close()
		for ; it.Valid(); it.Next() {
			key := it.Key()
			if !bytes.HasPrefix(key, nodePrefix) {
				continue
			}
			_, ok := keySet[string(key)]
			fmt.Println(key)
			require.Equal(true, ok, "unexpected node in db")
			delete(notVisited, string(key))
		}
	}
	fmt.Println("Verify nodes.....")
	checkNodes(rocksdb.cfIOTree)
	checkNodes(rocksdb.cfStateTree)

	require.Equal(0, len(notVisited), "some nodes not visited")
}

func checkNoLogKeys(require *require.Assertions, rocksdb *rocksdbNodeDB) {
	it := prefixIterator(rocksdb.db.NewIterator(defaultReadOptions), nil)
	defer it.Close()
	for ; it.Valid(); it.Next() {
		require.False(bytes.HasPrefix(it.Key(), logPrefix), "checkLogKeys()/iteration")
	}
}

func restoreCheckpoint(ctx *test, ckMeta *checkpoint.Metadata, ckNodes keySet) checkpoint.Restorer {
	fc, err := checkpoint.NewFileCreator(ctx.dir, ctx.rocksdb)
	ctx.require.NoError(err, "NewFileCreator() - 2")

	restorer, err := checkpoint.NewRestorer(ctx.rocksdb)
	ctx.require.NoError(err, "NewRestorer()")

	err = ctx.rocksdb.StartMultipartInsert(ckMeta.Root.Version)
	ctx.require.NoError(err, "StartMultipartInsert()")
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

	verifyNodes(ctx.require, ctx.rocksdb, ckMeta.Root.Version, ckNodes)

	return restorer
}

func TestMultipartRestore(t *testing.T) {
	ctx := context.Background()
	wrap := func(testFunc func(ctx *test), initialValues [][]byte) func(*testing.T) {
		return func(t *testing.T) {
			require := require.New(t)

			dir, err := os.MkdirTemp("", "oasis-storage-database-test")
			require.NoError(err, "TempDir()")
			defer os.RemoveAll(dir)

			ckMeta, ckNodes := createCheckpoint(ctx, require, dir, initialValues, 1)

			dbCfg := *dbCfg
			dbCfg.DB = dir
			ndb, err := New(&dbCfg)
			require.NoError(err, "New() - 2")
			defer ndb.Close()
			rocksdb := ndb.(*rocksdbNodeDB)

			testCtx := &test{
				require: require,
				ctx:     ctx,
				dir:     dir,
				rocksdb: rocksdb,
				ckMeta:  ckMeta,
				ckNodes: ckNodes,
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
	err = ctx.rocksdb.AbortMultipartInsert()
	ctx.require.NoError(err, "AbortMultipartInsert()")

	verifyNodes(ctx.require, ctx.rocksdb, 2, keySet{})
	checkNoLogKeys(ctx.require, ctx.rocksdb)
}

func testFinalize(ctx *test) {
	// Finalize a restore, check nodes again.
	// This time, all the restored nodes should be present, but the
	// log keys should be gone.
	restoreCheckpoint(ctx, ctx.ckMeta, ctx.ckNodes)

	// Test parameter sanity checking first.
	err := ctx.rocksdb.Finalize(nil)
	ctx.require.Error(err, "Finalize with no roots should fail")

	bogusRoot := ctx.ckMeta.Root
	bogusRoot.Version++
	err = ctx.rocksdb.Finalize([]node.Root{ctx.ckMeta.Root, bogusRoot})
	ctx.require.Error(err, "Finalize with roots from different versions should fail")

	err = ctx.rocksdb.Finalize([]node.Root{ctx.ckMeta.Root})
	ctx.require.NoError(err, "Finalize()")

	verifyNodes(ctx.require, ctx.rocksdb, ctx.ckMeta.Root.Version, ctx.ckNodes)
	checkNoLogKeys(ctx.require, ctx.rocksdb)
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
	err := ctx.rocksdb.Finalize([]node.Root{ctx.ckMeta.Root})
	ctx.require.NoError(err, "Finalize()")
	verifyNodes(ctx.require, ctx.rocksdb, 2, ctx.ckNodes)

	// Restore the second checkpoint. One of the nodes from it already exists. After aborting,
	// exactly the nodes from the first checkpoint should remain.
	restorer := restoreCheckpoint(ctx, ckMeta2, ckNodes2)
	err = restorer.AbortRestore(ctx.ctx)
	ctx.require.NoError(err, "AbortRestore()")
	err = ctx.rocksdb.AbortMultipartInsert()
	ctx.require.NoError(err, "AbortMultipartInsert()")
	verifyNodes(ctx.require, ctx.rocksdb, 2, ctx.ckNodes)
}
