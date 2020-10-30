package badger

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/dgraph-io/badger/v2"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

var (
	_ checkpoint.Checkpointer
	_ writelog.Iterator

	testKey1 = []byte("this key is marvellous")
	testVal1 = []byte("with a value to boot")
	testKey2 = []byte("and this key makes sure we have more than one node")
	testVal2 = []byte("double the values! double the magic!")

	testKey3 = []byte("this key shares a prefix")
	testVal3 = []byte("but not the value")

	testData = [][][]byte{ // nolint: deadcode, varcheck, unused
		{testKey1, testVal1},
		{testKey2, testVal2},
		{testKey3, testVal3},
	}
)

type testCase struct {
	PendingRoot    hash.Hash   `json:"pending_root"`
	LongRoots      []hash.Hash `json:"long_roots"`
	PendingVersion uint64      `json:"pending_version"`
	Entries        []testEntry `json:"entries"`
}

type testEntry struct {
	Key     []byte `json:"key"`
	Value   []byte `json:"value"`
	Version uint64 `json:"version"`
	Delete  bool   `json:"delete"`
}

func checkContents(ctx context.Context, t *testing.T, ndb api.NodeDB, root node.Root, testData [][][]byte) {
	// Check that keys are accessible.
	tree := mkvs.NewWithRoot(nil, ndb, root)
	require.NotNil(t, tree, "NewWithRoot")
	defer tree.Close()

	for i, e := range testData {
		val, err := tree.Get(ctx, e[0])
		require.NoError(t, err, fmt.Sprintf("Get-%d", i+1))
		require.Equal(t, e[1], val, fmt.Sprintf("Get-%d", i+1))
	}
}

func makeDB(t *testing.T, caseName string) (context.Context, api.NodeDB, *badgerNodeDB, testCase) {
	ctx := context.Background()
	ndb, err := New(dbCfg)
	bdb := ndb.(*badgerNodeDB)
	require.NoError(t, err, "New")
	return ctx, ndb, bdb, readDump(t, ndb, caseName)
}

type testMigrationHelper struct {
}

func (mh *testMigrationHelper) GetRootForHash(root hash.Hash, version uint64) ([]node.Root, error) {
	return []node.Root{{
		Namespace: testNs,
		Version:   version,
		Type:      node.RootTypeState,
		Hash:      root,
	}}, nil
}

func (mh *testMigrationHelper) DisplayStepBegin(msg string) {
	// Nothing to do here for testing.
}

func (mh *testMigrationHelper) DisplayStepEnd(msg string) {
	// Nothing to do here for testing.
}

func (mh *testMigrationHelper) DisplayStep(msg string) {
	// Nothing to do here for testing.
}

func (mh *testMigrationHelper) DisplayProgress(msg string, current, total uint64) {
	// Nothing to fo here for testing.
}

func TestBadgerV4MigrationSimple(t *testing.T) {
	ctx, ndb, bdb, tc := makeDB(t, "case-nonfinalized.json")
	defer ndb.Close()
	helper := &testMigrationHelper{}

	migrator := originVersions[3](bdb, helper)
	newVersion, err := migrator.Migrate()
	require.NoError(t, err, "Migrate")
	require.Equal(t, uint64(4), newVersion, "Migrate")

	// Start using the migrated v4 database.
	err = bdb.load()
	require.NoError(t, err, "load")

	finalRoot := node.Root{
		Namespace: testNs,
		Version:   2,
		Type:      node.RootTypeState,
		Hash:      tc.PendingRoot,
	}
	err = ndb.Finalize(ctx, []node.Root{finalRoot})
	require.NoError(t, err, "Finalize")

	checkContents(ctx, t, ndb, finalRoot, testData)
}

func TestBadgerV4MigrationChunks(t *testing.T) {
	ctx, ndb, bdb, tc := makeDB(t, "case-chunkrestore.json")
	defer ndb.Close()
	helper := &testMigrationHelper{}

	migrator := originVersions[3](bdb, helper)
	newVersion, err := migrator.Migrate()
	require.NoError(t, err, "Migrate")
	require.Equal(t, uint64(4), newVersion, "Migrate")

	// Start using the migrated v4 database.
	err = bdb.load()
	require.NoError(t, err, "load")

	// There should be some multipart log keys in the migrated database.
	checkMultipart := func() bool {
		txn := bdb.db.NewTransactionAt(tsMetadata, false)
		defer txn.Discard()

		opts := badger.DefaultIteratorOptions
		opts.Prefix = v4MultipartRestoreNodeLogKeyFmt.Encode()
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			return true
		}
		return false
	}
	require.Equal(t, true, checkMultipart(), "checkMultipart-1")

	finalRoot := node.Root{
		Namespace: testNs,
		Version:   2,
		Type:      node.RootTypeState,
		Hash:      tc.PendingRoot,
	}
	bdb.multipartVersion = 2 // Simulate state in the middle of a chunk restore.
	err = ndb.Finalize(ctx, []node.Root{finalRoot})
	require.NoError(t, err, "Finalize")

	require.Equal(t, false, checkMultipart(), "checkMultipart-2")
	checkContents(ctx, t, ndb, finalRoot, testData)
}

type crashyMigrationHelper struct {
	testMigrationHelper

	metaCount int
}

const panicObj = "migration interruption"

func (ch *crashyMigrationHelper) GetRootForHash(root hash.Hash, version uint64) ([]node.Root, error) {
	defer func() {
		ch.metaCount--
	}()
	if ch.metaCount == 0 {
		panic(fmt.Errorf("%s", panicObj))
	}
	return ch.testMigrationHelper.GetRootForHash(root, version)
}

func TestBadgerV4MigrationCrashMeta(t *testing.T) {
	ctx, ndb, bdb, tc := makeDB(t, "case-nonfinalized.json")
	defer ndb.Close()
	helper := &crashyMigrationHelper{
		metaCount: 3,
	}

	// The first migration run should crash and leave behind a migration key.
	migrator := originVersions[3](bdb, helper)
	require.PanicsWithError(t, panicObj, func() { _, _ = migrator.Migrate() }, "Migrate-panic")

	err := bdb.load()
	require.Errorf(t, err, "mkvs: database upgrade in progress")

	// The second run should be able to complete the migration.
	newVersion, err := migrator.Migrate()
	require.NoError(t, err, "Migrate")
	require.Equal(t, uint64(4), newVersion, "Migrate")

	// Start using the migrated v4 database.
	err = bdb.load()
	require.NoError(t, err, "load")

	finalRoot := node.Root{
		Namespace: testNs,
		Version:   2,
		Type:      node.RootTypeState,
		Hash:      tc.PendingRoot,
	}
	err = ndb.Finalize(ctx, []node.Root{finalRoot})
	require.NoError(t, err, "Finalize")

	checkContents(ctx, t, ndb, finalRoot, testData)
}

type sharedRootMigrationHelper struct {
	testMigrationHelper
}

func (sh *sharedRootMigrationHelper) GetRootForHash(root hash.Hash, version uint64) ([]node.Root, error) {
	return []node.Root{
		{
			Namespace: testNs,
			Version:   version,
			Type:      node.RootTypeState,
			Hash:      root,
		},
		{
			Namespace: testNs,
			Version:   version,
			Type:      node.RootTypeIO,
			Hash:      root,
		},
	}, nil
}

func TestBadgerV4SharedRoots(t *testing.T) {
	ctx, ndb, bdb, tc := makeDB(t, "case-long.json")
	defer ndb.Close()
	helper := &sharedRootMigrationHelper{}

	migrator := originVersions[3](bdb, helper)
	newVersion, err := migrator.Migrate()
	require.NoError(t, err, "Migrate")
	require.Equal(t, uint64(4), newVersion, "Migrate")

	// Start using the migrated v4 database.
	err = bdb.load()
	require.NoError(t, err, "load")

	// prettyPrintDBV4(ndb)
	rounds := uint64(len(tc.LongRoots))

	// Finalize the last round first.
	err = ndb.Finalize(ctx, []node.Root{
		{
			Namespace: testNs,
			Version:   rounds,
			Type:      node.RootTypeState,
			Hash:      tc.LongRoots[rounds-1],
		},
		{
			Namespace: testNs,
			Version:   rounds,
			Type:      node.RootTypeIO,
			Hash:      tc.LongRoots[rounds-1],
		},
	})
	require.NoError(t, err, "Finalize")

	allTypes := []node.RootType{
		node.RootTypeState,
		node.RootTypeIO,
	}
	for round := uint64(1); round < rounds; round++ {
		// Check key accessibility for this round.
		for _, typ := range allTypes {
			root := node.Root{
				Namespace: testNs,
				Version:   round,
				Type:      typ,
				Hash:      tc.LongRoots[round-1],
			}
			tree := mkvs.NewWithRoot(nil, ndb, root)
			require.NotNil(t, tree, "NewWithRoot")
			for i := 1; i < 5; i++ {
				key, val := mkLongKV(round, i)
				var treeVal []byte
				treeVal, err = tree.Get(ctx, key)
				require.NoError(t, err, fmt.Sprintf("Get round %d, key %d", round, i))
				require.Equal(t, val, treeVal, fmt.Sprintf("Value round %d, key %d", round, i))
			}
			tree.Close()
		}

		// Some extra checks.
		err = checkSanityInternal(ctx, bdb, helper)
		require.NoError(t, err, fmt.Sprintf("checkSanityInternal/%d", round))

		// Try pruning, then move on. The following rounds should all still work.
		err = ndb.Prune(ctx, round)
		require.NoError(t, err, fmt.Sprintf("Prune/%d", round))
	}
	// prettyPrintDBV4(ndb)
}

func TestBadgerV4KeyVersioning(t *testing.T) {
	// case-long has some keys that are both inserted and then deleted in
	// a later version. All of these should be migrated and readable as V4 keys.
	_, ndb, bdb, _ := makeDB(t, "case-long.json")
	defer ndb.Close()
	helper := &sharedRootMigrationHelper{}

	migrator := originVersions[3](bdb, helper)
	newVersion, err := migrator.Migrate()
	require.NoError(t, err, "Migrate")
	require.Equal(t, uint64(4), newVersion, "Migrate")

	// Start using the migrated v4 database.
	err = bdb.load()
	require.NoError(t, err, "load")

	txn := bdb.db.NewTransactionAt(math.MaxUint64, false)
	defer txn.Discard()
	itOpts := badger.DefaultIteratorOptions
	itOpts.AllVersions = true
	it := txn.NewIterator(itOpts)
	defer it.Close()

	// The GC can't run in in-memory databases, so this is
	// an unfortunate necessary step. Find all keys with no associated values in the db
	// (i.e. ones with only deletion flags).
	valuedKeys := map[string]bool{}
	for it.Rewind(); it.Valid(); it.Next() {
		key := fmt.Sprintf("%v", it.Item().Key())
		valuedKeys[key] = valuedKeys[key] || !it.Item().IsDeletedOrExpired()
	}

	var h hash.Hash
	var th1, th2 typedHash
	var v uint64

	for it.Rewind(); it.Valid(); it.Next() {
		val, _ := it.Item().ValueCopy(nil)
		key := it.Item().Key()
		skippable := fmt.Sprintf("%v", key)
		if valuedKeys[skippable] == false {
			continue
		}
		switch {
		case nodeKeyFmt.Decode(key, &h):
			// Nothing to do.
		case writeLogKeyFmt.Decode(key, &v, &th1, &th2):
			// Nothing to do.
		case rootsMetadataKeyFmt.Decode(key, &v):
			if !it.Item().IsDeletedOrExpired() {
				meta := rootsMetadata{}
				err = cbor.UnmarshalTrusted(val, &meta)
				require.NoError(t, err, "rootsMetadata cbor unmarshal")
			}
		case rootUpdatedNodesKeyFmt.Decode(key, &v, &th1):
			// Nothing to do.
		case multipartRestoreNodeLogKeyFmt.Decode(key, &th1):
			// Nothing to do.
		case rootNodeKeyFmt.Decode(key, &th1):
			// Nothing to do.
		case metadataKeyFmt.Decode(key):
			// Nothing to do.
		default:
			require.FailNow(t, "unknown key")
		}
	}
}

func prettyPrintDBV4(ndb api.NodeDB) { // nolint: deadcode, unused
	db := ndb.(*badgerNodeDB).db
	txn := db.NewTransactionAt(math.MaxUint64, false)
	defer txn.Discard()
	itOpts := badger.DefaultIteratorOptions
	itOpts.AllVersions = true
	it := txn.NewIterator(itOpts)
	defer it.Close()

	var h hash.Hash
	var th1, th2 typedHash
	var v uint64

	for it.Rewind(); it.Valid(); it.Next() {
		val, _ := it.Item().ValueCopy(nil)
		key := it.Item().Key()
		if it.Item().IsDeletedOrExpired() {
			fmt.Printf("deleted @ %v, ", it.Item().Version())
		} else {
			fmt.Printf("inserted @ %v, ", it.Item().Version())
		}
		switch {
		case nodeKeyFmt.Decode(key, &h):
			fmt.Printf("node %v\n", h)
		case writeLogKeyFmt.Decode(key, &v, &th1, &th2):
			fmt.Printf("write log @ %v, %v -> %v\n", v, th1, th2)
		case rootsMetadataKeyFmt.Decode(key, &v):
			fmt.Printf("roots metadata @ %v:\n", v)
			if !it.Item().IsDeletedOrExpired() {
				meta := rootsMetadata{}
				_ = cbor.UnmarshalTrusted(val, &meta)
				for root, chain := range meta.Roots {
					fmt.Printf("- %v -> %v\n", root, chain)
				}
			}
		case rootUpdatedNodesKeyFmt.Decode(key, &v, &th1):
			fmt.Printf("root updated nodes @ %v, %v\n", v, th1)
		case multipartRestoreNodeLogKeyFmt.Decode(key, &th1):
			fmt.Printf("multipart restore node %v\n", th1)
		case rootNodeKeyFmt.Decode(key, &th1):
			fmt.Printf("root node marker %v\n", th1)
		}
	}
}

func readDump(t *testing.T, ndb api.NodeDB, caseName string) (tc testCase) { // nolint: deadcode, unused
	data, err := ioutil.ReadFile(filepath.Join("testdata", caseName))
	require.NoError(t, err, "ReadFile")
	err = json.Unmarshal(data, &tc)
	require.NoError(t, err, "Unmarshal")

	b := ndb.(*badgerNodeDB).db.NewWriteBatchAt(1)
	defer b.Cancel()
	for _, e := range tc.Entries {
		if e.Delete {
			err = b.DeleteAt(e.Key, e.Version)
			require.NoError(t, err, "readDump/DeleteAt")
		} else {
			err = b.SetEntryAt(badger.NewEntry(e.Key, e.Value), e.Version)
			require.NoError(t, err, "readDump/SetEntryAt")
		}
	}
	b.Flush()
	return
}

func dumpDB(ndb api.NodeDB, caseName string, tc testCase) { // nolint: deadcode, unused
	db := ndb.(*badgerNodeDB).db
	txn := db.NewTransactionAt(math.MaxUint64, false)
	defer txn.Discard()
	itOpts := badger.DefaultIteratorOptions
	itOpts.AllVersions = true
	it := txn.NewIterator(itOpts)
	defer it.Close()

	for it.Rewind(); it.Valid(); it.Next() {
		val, _ := it.Item().ValueCopy(nil)
		entry := testEntry{
			Key:     it.Item().KeyCopy(nil),
			Value:   val,
			Version: it.Item().Version(),
		}
		// Versions are iterated over in reverse order (from high to low), but that's fine;
		// badger can delete a key that doesn't exist yet, which simplifies things.
		if it.Item().IsDeletedOrExpired() {
			entry.Delete = true
		}
		tc.Entries = append(tc.Entries, entry)
	}
	if caseName != "" {
		marshalled, _ := json.MarshalIndent(tc, "", "\t")
		_ = ioutil.WriteFile(filepath.Join("testdata", caseName), marshalled, os.FileMode(0o666))
	}
}

func mkLongKV(round uint64, key int) ([]byte, []byte) {
	return []byte(fmt.Sprintf("test key; round %d with %d index", round, key)),
		[]byte(fmt.Sprintf("interesting value %d.%d", round, key))
}

/*func prettyPrintDBV3(ndb api.NodeDB) {
	db := ndb.(*badgerNodeDB).db
	txn := db.NewTransactionAt(math.MaxUint64, false)
	defer txn.Discard()
	itOpts := badger.DefaultIteratorOptions
	itOpts.AllVersions = true
	it := txn.NewIterator(itOpts)
	defer it.Close()

	var h hash.Hash
	var h1, h2 hash.Hash
	var v uint64

	for it.Rewind(); it.Valid(); it.Next() {
		val, _ := it.Item().ValueCopy(nil)
		key := it.Item().Key()
		if it.Item().IsDeletedOrExpired() {
			fmt.Printf("deleted @ %v, ", it.Item().Version())
		} else {
			fmt.Printf("inserted @ %v, ", it.Item().Version())
		}
		switch {
		case nodeKeyFmt.Decode(key, &h):
			fmt.Printf("node %v\n", h)
		case writeLogKeyFmt.Decode(key, &v, &h1, &h2):
			fmt.Printf("write log @ %v, %v -> %v\n", v, h1, h2)
		case rootsMetadataKeyFmt.Decode(key, &v):
			fmt.Printf("roots metadata @ %v:\n", v)
			if !it.Item().IsDeletedOrExpired() {
				meta := rootsMetadata{}
				_ = cbor.UnmarshalTrusted(val, &meta)
				for root, chain := range meta.Roots {
					fmt.Printf("- %v -> %v\n", root, chain)
				}
			}
		case rootUpdatedNodesKeyFmt.Decode(key, &v, &h1):
			fmt.Printf("root updated nodes @ %v, %v\n", v, h1)
		case multipartRestoreNodeLogKeyFmt.Decode(key, &h1):
			fmt.Printf("multipart restore node %v\n", h1)
		}
	}
}

// Use this to produce v3 database contents on a commit before dbVersion = 4.
func TestBadgerV3InitialFill(t *testing.T) {
	ctx := context.Background()

	initialFill := func(ndb api.NodeDB) mkvs.Tree {
		emptyRoot := node.Root{
			Namespace: testNs,
			Version:   0,
		}
		emptyRoot.Hash.Empty()

		tree := mkvs.NewWithRoot(nil, ndb, emptyRoot)
		require.NotNil(t, tree, "NewWithRoot")

		wl := writelog.WriteLog{
			{
				Key:   testKey1,
				Value: testVal1,
			},
			{
				Key:   testKey2,
				Value: testVal2,
			},
		}

		// One fully finalized round.
		err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(wl))
		require.NoError(t, err, "ApplyWriteLog")
		_, rootHash, err := tree.Commit(ctx, testNs, 1)
		require.NoError(t, err, "Commit")
		err = ndb.Finalize(ctx, 1, []hash.Hash{rootHash})
		require.NoError(t, err, "Finalize")

		return tree
	}

	ndb, err := New(dbCfg)
	require.NoError(t, err, "New")
	defer ndb.Close()
	tree := initialFill(ndb)

	wl := writelog.WriteLog{
		{
			Key:   testKey3,
			Value: testVal3,
		},
	}

	// And also some dangling pending nodes. The upgraded database should be able to
	// finalize all of this and start usefully returning keys.
	err = tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(wl))
	require.NoError(t, err, "ApplyWriteLog")
	_, newRootHash, err := tree.Commit(ctx, testNs, 2)
	require.NoError(t, err, "Commit")
	tree.Close()

	// Dump everything.
	dumpDB(ndb, "case-nonfinalized.json", testCase{
		PendingRoot:    newRootHash,
		PendingVersion: 2,
	})

	// Now finalize and create a checkpoint. Then we'll restore it but leave finalization
	// until after the migration.
	err = ndb.Finalize(ctx, 2, []hash.Hash{newRootHash})
	require.NoError(t, err, "Finalize")

	dir, err := ioutil.TempDir("", "oasis-storage-database-test")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dir)

	fc, err := checkpoint.NewFileCreator(dir, ndb)
	require.NoError(t, err, "NewFileCreator")
	ckMeta, err := fc.CreateCheckpoint(ctx, node.Root{
		Namespace: testNs,
		Version:   2,
		Hash:      newRootHash,
	}, 1024*1024)
	require.NoError(t, err, "CreateCheckpoint")

	// New db, start restoring the chunk into it.
	// NOTE: The code assumes there's only a single chunk in the checkpoint.
	newdb, err := New(dbCfg)
	require.NoError(t, err, "New")
	defer newdb.Close()
	initialFill(newdb).Close()
	// fc, err = checkpoint.NewFileCreator(dir, ndb)
	// require.NoError(t, err, "NewFileCreator")
	restorer, err := checkpoint.NewRestorer(newdb)
	require.NoError(t, err, "NewRestorer")
	err = restorer.StartRestore(ctx, ckMeta)
	require.NoError(t, err, "StartRestore")
	chunkMeta, err := ckMeta.GetChunkMetadata(0)
	require.NoError(t, err, "GetChunkMetadata")
	r, w, _ := os.Pipe()
	go func() {
		_ = fc.GetCheckpointChunk(ctx, chunkMeta, w)
		w.Close()
	}()
	_, err = restorer.RestoreChunk(ctx, 0, r)
	require.NoError(t, err, "RestoreChunk")
	require.NoError(t, err, "GetCheckpointChunk")
	dumpDB(newdb, "case-chunkrestore.json", testCase{
		PendingRoot:    ckMeta.Root.Hash,
		PendingVersion: ckMeta.Root.Version,
	})
}

// Produce multiple rounds with predictable keys and a degree of sharing in
// the tree nodes. Leave out finalization for the last one.
func TestBadgerV3MultiroundFill(t *testing.T) {
	ctx := context.Background()

	ndb, err := New(dbCfg)
	require.NoError(t, err, "New")
	defer ndb.Close()

	emptyRoot := node.Root{
		Namespace: testNs,
		Version:   0,
	}
	emptyRoot.Hash.Empty()

	tree := mkvs.NewWithRoot(nil, ndb, emptyRoot)
	require.NotNil(t, tree, "NewWithRoot")

	tc := testCase{}

	maxRound := uint64(10)
	for round := uint64(1); round < maxRound; round++ {
		wl := writelog.WriteLog{}
		for i := 1; i < 5; i++ {
			key, val := mkLongKV(round, i)
			wl = append(wl, writelog.LogEntry{Key: key, Value: val})
		}
		err := tree.ApplyWriteLog(ctx, writelog.NewStaticIterator(wl))
		require.NoError(t, err, "ApplyWriteLog")

		_, rootHash, err := tree.Commit(ctx, testNs, round)
		require.NoError(t, err, "Commit")
		tc.LongRoots = append(tc.LongRoots, rootHash)
		if round < maxRound-1 {
			err = ndb.Finalize(ctx, round, []hash.Hash{rootHash})
			require.NoError(t, err, "Finalize")
		}
	}
	tree.Close()

	// Dump everything.
	dumpDB(ndb, "case-long.json", tc)
	prettyPrintDBV3(ndb)
}*/
