package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	dbAPI "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/pathbadger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const testVersion uint64 = 10

var testNs common.Namespace = common.NewTestNamespaceFromSeed([]byte("test namespace"), 0)

func TestCreateCheckpoints(t *testing.T) {
	t.Run("fails on non-empty output dir", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}
		ndb, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer ndb.Close()

		stateRoot := commitRoot(ctx, t, ndb, ns, testVersion, node.RootTypeState, map[string]string{
			"key": "value",
		})
		require.NoError(t, ndb.Finalize([]node.Root{stateRoot}))

		outDir := filepath.Join(t.TempDir(), "checkpoints")
		require.NoError(t, os.Mkdir(outDir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(outDir, "existing"), []byte{}, 0o600))

		err = createCheckpoints(ctx, ndb, ns, testVersion, outDir)
		require.Error(t, err, "createCheckpoints should fail for non-empty output directory")
	})

	t.Run("fails on empty node DB", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}
		ndb, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer ndb.Close()

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		err = createCheckpoints(ctx, ndb, ns, testVersion, cpDir)
		require.Error(t, err, "createCheckpoints should fail for empty node database")
	})

	t.Run("fails when version is before earliest", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}
		ndb, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer ndb.Close()

		stateRoot := commitRoot(ctx, t, ndb, ns, testVersion, node.RootTypeState, map[string]string{
			"key": "value",
		})
		require.NoError(t, ndb.Finalize([]node.Root{stateRoot}))

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		err = createCheckpoints(ctx, ndb, ns, testVersion-1, cpDir)
		require.Error(t, err, "createCheckpoints should fail for version before earliest")
	})

	t.Run("fails when version is after latest", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}
		ndb, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer ndb.Close()

		stateRoot := commitRoot(ctx, t, ndb, ns, testVersion, node.RootTypeState, map[string]string{
			"key": "value",
		})
		require.NoError(t, ndb.Finalize([]node.Root{stateRoot}))

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		err = createCheckpoints(ctx, ndb, ns, testVersion+1, cpDir)
		require.Error(t, err, "createCheckpoints should fail for version after latest")
	})
}

func TestImportCheckpoints(t *testing.T) {
	t.Run("fails on non-empty destination DB", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}

		srcNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer srcNDB.Close()

		stateRoot := commitRoot(ctx, t, srcNDB, ns, testVersion, node.RootTypeState, map[string]string{
			"key": "value",
		})
		require.NoError(t, srcNDB.Finalize([]node.Root{stateRoot}))

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, createCheckpoints(ctx, srcNDB, ns, testVersion, cpDir))

		dstNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer dstNDB.Close()

		// NodeDB allows restoring checkpoint even if the target NodeDB is not empty,
		// as long as the checkpoint is younger than the the last finalized version.
		// We don't want that, thus finalizing testVersion-1 to ensure createCheckpoints
		// guard is tested and that the test does not rely on mkvs version already finalized.
		err = dstNDB.Finalize([]node.Root{emptyRoot(ns, testVersion-1, node.RootTypeState)})
		require.NoError(t, err)

		err = restoreCheckpoints(ctx, dstNDB, ns, cpDir)
		require.Error(t, err, "restoreCheckpoints should fail for non-empty destination database")
	})

	t.Run("fails on empty input dir", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}
		ndb, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer ndb.Close()

		err = restoreCheckpoints(ctx, ndb, ns, t.TempDir())
		require.Error(t, err, "restoreCheckpoints should fail for empty input directory")
	})
}

func TestCreateImportRoundtrip(t *testing.T) {
	t.Run("single non-empty checkpoint", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}

		srcNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer srcNDB.Close()

		stateRoot := commitRoot(ctx, t, srcNDB, ns, testVersion, node.RootTypeState, map[string]string{
			"key": "value",
		})
		require.NoError(t, srcNDB.Finalize([]node.Root{stateRoot}))

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, createCheckpoints(ctx, srcNDB, ns, testVersion, cpDir))

		dstNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer dstNDB.Close()

		require.NoError(t, restoreCheckpoints(ctx, dstNDB, ns, cpDir))

		roots, err := dstNDB.GetRootsForVersion(testVersion)
		require.NoError(t, err)
		require.Equal(t, []node.Root{stateRoot}, roots)
		require.True(t, dstNDB.HasRoot(stateRoot))
	})

	t.Run("empty root is restored", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := common.Namespace{}
		stateRoot := emptyRoot(ns, testVersion, node.RootTypeState)

		srcNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer srcNDB.Close()

		require.NoError(t, srcNDB.Finalize([]node.Root{stateRoot}))

		latest, ok := srcNDB.GetLatestVersion()
		require.True(t, ok)
		require.EqualValues(t, testVersion, latest)

		// Empty roots are implicit yet GetRootForVersion does not return them.
		roots, err := srcNDB.GetRootsForVersion(testVersion)
		require.NoError(t, err)
		require.Empty(t, roots)
		require.True(t, srcNDB.HasRoot(stateRoot))

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, createCheckpoints(ctx, srcNDB, ns, testVersion, cpDir))

		dstNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer dstNDB.Close()

		require.NoError(t, restoreCheckpoints(ctx, dstNDB, ns, cpDir))

		latest, ok = dstNDB.GetLatestVersion()
		require.True(t, ok)
		require.EqualValues(t, testVersion, latest)

		roots, err = dstNDB.GetRootsForVersion(testVersion)
		require.NoError(t, err)
		// Via checkpoint roundtrip, empty state can be materialized as an explicit root,
		// which technically makes checkpoint restoration not 1:1 match. Same issue would
		// happen with checkpointer if this case would be ever triggered.
		require.Contains(t, roots, stateRoot)
		require.True(t, dstNDB.HasRoot(stateRoot))
	})

	t.Run("two non-empty roots (state and io)", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		srcNDB, err := newTestNodeDB(t, testNs)
		require.NoError(t, err)
		defer srcNDB.Close()

		stateRoot := commitRoot(ctx, t, srcNDB, testNs, testVersion, node.RootTypeState, map[string]string{
			"state-key": "state-value",
		})
		ioRoot := commitRoot(ctx, t, srcNDB, testNs, testVersion, node.RootTypeIO, map[string]string{
			"io-key": "io-value",
		})
		require.NoError(t, srcNDB.Finalize([]node.Root{stateRoot, ioRoot}))

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, createCheckpoints(ctx, srcNDB, testNs, testVersion, cpDir))

		dstNDB, err := newTestNodeDB(t, testNs)
		require.NoError(t, err)
		defer dstNDB.Close()

		require.NoError(t, restoreCheckpoints(ctx, dstNDB, testNs, cpDir))

		roots, err := dstNDB.GetRootsForVersion(testVersion)
		require.NoError(t, err)
		require.ElementsMatch(t, []node.Root{stateRoot, ioRoot}, roots)
	})

	t.Run("non-empty state root and empty io root", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()

		srcNDB, err := newTestNodeDB(t, testNs)
		require.NoError(t, err)
		defer srcNDB.Close()

		stateRoot := commitRoot(ctx, t, srcNDB, testNs, testVersion, node.RootTypeState, map[string]string{
			"state-key": "state-value",
		})
		ioRoot := emptyRoot(testNs, testVersion, node.RootTypeIO)
		require.NoError(t, srcNDB.Finalize([]node.Root{stateRoot, ioRoot}))

		cpDir := filepath.Join(t.TempDir(), "checkpoint")
		require.NoError(t, createCheckpoints(ctx, srcNDB, testNs, testVersion, cpDir))

		dstNDB, err := newTestNodeDB(t, testNs)
		require.NoError(t, err)
		defer dstNDB.Close()

		require.NoError(t, restoreCheckpoints(ctx, dstNDB, testNs, cpDir))

		roots, err := dstNDB.GetRootsForVersion(testVersion)
		require.NoError(t, err)
		require.Contains(t, roots, stateRoot)
		require.True(t, dstNDB.HasRoot(stateRoot))
		require.True(t, dstNDB.HasRoot(ioRoot))
	})
}

func newTestNodeDB(t *testing.T, ns common.Namespace) (dbAPI.NodeDB, error) {
	t.Helper()

	return pathbadger.New(&dbAPI.Config{
		DB:         filepath.Join(t.TempDir(), "db"),
		Namespace:  ns,
		MemoryOnly: true,
	})
}

func commitRoot(
	ctx context.Context,
	t *testing.T,
	ndb dbAPI.NodeDB,
	ns common.Namespace,
	version uint64,
	rootType node.RootType,
	data map[string]string,
) node.Root {
	t.Helper()

	tree := mkvs.New(nil, ndb, rootType)
	defer tree.Close()

	for k, v := range data {
		require.NoError(t, tree.Insert(ctx, []byte(k), []byte(v)))
	}

	_, rootHash, err := tree.Commit(ctx, ns, version)
	require.NoError(t, err)

	return node.Root{
		Namespace: ns,
		Version:   version,
		Type:      rootType,
		Hash:      rootHash,
	}
}

func emptyRoot(ns common.Namespace, version uint64, rootType node.RootType) node.Root {
	root := node.Root{
		Namespace: ns,
		Version:   version,
		Type:      rootType,
	}
	root.Hash.Empty()
	return root
}
