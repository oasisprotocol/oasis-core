package db_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	badgerDb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/rocksdb"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	writeLogSize = 100
)

var (
	testNs = common.NewTestNamespaceFromSeed([]byte("oasis db test ns"), 0)
	dbCfg  = &api.Config{
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

// NodeDBFactory is a function that creates a new node database for the given config.
type NodeDBFactory func(cfg *api.Config) (api.NodeDB, error)

func makeWriteLog() writelog.WriteLog {
	wl := make(writelog.WriteLog, writeLogSize)

	for i := 0; i < writeLogSize; i++ {
		wl[i] = writelog.LogEntry{
			Key:   []byte(fmt.Sprintf("key %d", i)),
			Value: []byte(fmt.Sprintf("value %d", i)),
		}
	}

	return wl
}

func TestHashedWriteLog(t *testing.T) {
	wl := makeWriteLog()
	wla := make(writelog.Annotations, len(wl))
	hashes := make(map[hash.Hash]*node.Pointer)
	for i := 0; i < len(wl); i++ {
		h := hash.NewFromBytes(wl[i].Value)
		ptr := &node.Pointer{
			Clean: true,
			Hash:  h,
			Node: &node.LeafNode{
				Clean: true,
				Hash:  h,
				Key:   wl[i].Key,
				Value: wl[i].Value,
			},
		}
		wla[i] = writelog.LogEntryAnnotation{
			InsertedNode: ptr,
		}
		hashes[ptr.Hash] = ptr
	}

	hashed := api.MakeHashedDBWriteLog(wl, wla)

	var done bool
	it, err := api.ReviveHashedDBWriteLogs(context.Background(),
		func() (node.Root, api.HashedDBWriteLog, error) {
			if done {
				return node.Root{}, nil, nil
			}
			done = true

			return node.Root{}, hashed, nil
		},
		func(root node.Root, h hash.Hash) (*node.LeafNode, error) {
			return hashes[h].Node.(*node.LeafNode), nil
		},
		func() {},
	)
	require.NoError(t, err, "ReviveHashedDBWriteLogs")

	i := 0
	for {
		more, err := it.Next()
		require.NoError(t, err, "it.Next()")
		if !more {
			break
		}
		entry, err := it.Value()
		require.NoError(t, err, "it.Value()")
		require.Equal(t, entry, wl[i])
		i++
	}
	require.Equal(t, i, len(wl))
}

func TestBadgerBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (NodeDBFactory, func()) {
		// Create a new random temporary directory under /tmp.
		dir, err := os.MkdirTemp("", "mkvs.test.badger")
		require.NoError(t, err, "TempDir")

		// Create a Badger-backed Node DB factory.
		factory := func(cfg *api.Config) (api.NodeDB, error) {
			if cfg.DB == "" {
				cfg.DB = dir
			}
			return badgerDb.New(cfg)
		}

		cleanup := func() {
			os.RemoveAll(dir)
		}

		return factory, cleanup
	}, nil)
}

func TestRocksDBBackend(t *testing.T) {
	testBackend(t, func(t *testing.T) (NodeDBFactory, func()) {
		// Create a new random temporary directory under /tmp.
		dir, err := os.MkdirTemp("", "mkvs.test.rocksdb")
		require.NoError(t, err, "TempDir")

		// Create a RocksDB-backed Node DB factory.
		factory := func(cfg *api.Config) (api.NodeDB, error) {
			if cfg.DB == "" {
				cfg.DB = dir
			}
			return rocksdb.New(cfg)
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
		{"FinalizeBasic", testFinalizeBasic},
		{"VersionChecks", testVersionChecks},
		{"ReadOnlyBatch", testReadOnlyBatch},
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

func testFinalizeBasic(t *testing.T, new NodeDBFactory) {
	ctx := context.Background()
	require := require.New(t)

	offset := func(vals [][]byte) [][]byte {
		ret := make([][]byte, 0, len(vals))
		for _, val := range vals {
			ret = append(ret, append(val, 0x0a))
		}
		return ret
	}

	ndb, err := new(dbCfg)
	require.NoError(err, "New()")
	defer ndb.Close()

	root1 := fillDB(ctx, require, testValues, nil, 1, 2, ndb)
	err = ndb.Finalize([]node.Root{root1})
	require.NoError(err, "Finalize({root1})")

	// Finalize a corrupted root.
	currentValues := offset(testValues)
	root2 := fillDB(ctx, require, currentValues, &root1, 2, 3, ndb)
	root2.Hash[3]++
	err = ndb.Finalize([]node.Root{root2})
	require.Errorf(err, "mkvs: root not found", "Finalize({root2-broken})")
}

func testVersionChecks(t *testing.T, new NodeDBFactory) {
	require := require.New(t)
	ndb, err := new(dbCfg)
	require.NoError(err, "New()")
	defer ndb.Close()

	err = ndb.StartMultipartInsert(0)
	require.Error(err, "StartMultipartInsert(0)")

	err = ndb.StartMultipartInsert(42)
	require.NoError(err, "StartMultipartInsert(42)")
	err = ndb.StartMultipartInsert(44)
	require.Error(err, "StartMultipartInsert(44)")

	root := node.Root{Type: node.RootTypeState}
	_, err = ndb.NewBatch(root, 0, false) // Normal chunks not allowed during multipart.
	require.Error(err, "NewBatch(.., 0, false)")
	_, err = ndb.NewBatch(root, 13, true)
	require.Error(err, "NewBatch(.., 13, true)")
	batch, err := ndb.NewBatch(root, 42, true)
	require.NoError(err, "NewBatch(.., 42, true)")
	defer batch.Reset()

	err = batch.Commit(root)
	require.Error(err, "Commit(Root{0})")
}

func testReadOnlyBatch(t *testing.T, new NodeDBFactory) {
	require := require.New(t)

	// No way to initialize a readonly-database, so it needs to be created rw first.
	// This means we need persistence.
	dir, err := os.MkdirTemp("", "oasis-storage-database-test")
	require.NoError(err, "TempDir()")
	defer os.RemoveAll(dir)

	readonlyCfg := *dbCfg
	readonlyCfg.MemoryOnly = false
	readonlyCfg.ReadOnly = false
	readonlyCfg.DB = dir

	func() {
		ndb, errRw := new(&readonlyCfg)
		require.NoError(errRw, "New() - 1")
		defer ndb.Close()
	}()

	readonlyCfg.ReadOnly = true
	ndb, err := new(&readonlyCfg)
	require.NoError(err, "New() - 2")
	defer ndb.Close()

	_, err = ndb.NewBatch(node.Root{}, 13, false)
	require.Error(err, "NewBatch()")
}
