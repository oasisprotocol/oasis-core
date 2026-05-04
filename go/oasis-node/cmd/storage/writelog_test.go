package storage

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	mkvsAPI "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

func TestWriteLogImport(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := testNs

		srcNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer srcNDB.Close()

		srcRoots, err := populateNDB(ctx, srcNDB, ns)
		require.NoError(t, err)
		trustedRoots := newTestTrustedProvider(srcRoots)

		var buf bytes.Buffer
		exporter, err := newWriteLogExporter(srcNDB, ns, 1, 10, &buf)
		require.NoError(t, err)
		err = exporter.export(ctx)
		require.NoError(t, err)

		dstNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer dstNDB.Close()

		reader := bytes.NewReader(buf.Bytes())
		importer, err := newWriteLogImporter(dstNDB, ns, trustedRoots, 10, reader)
		require.NoError(t, err)
		err = importer.importUntrusted(ctx)
		require.NoError(t, err)

		requireSameFinalizedRoots(t, srcNDB, dstNDB, 1, 10)
	})

	t.Run("fails when metadata starts after required start version", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := testNs

		srcNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer srcNDB.Close()

		srcRoots, err := populateNDB(ctx, srcNDB, ns)
		require.NoError(t, err)
		trustedProvider := newTestTrustedProvider(srcRoots)

		var buf bytes.Buffer
		exporter, err := newWriteLogExporter(srcNDB, ns, 2, 10, &buf)
		require.NoError(t, err)
		err = exporter.export(ctx)
		require.NoError(t, err)

		dstNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer dstNDB.Close()

		reader := bytes.NewReader(buf.Bytes())
		_, err = newWriteLogImporter(dstNDB, ns, trustedProvider, 10, reader)
		require.ErrorContains(t, err, "metadata starts after required start version")
	})

	t.Run("fails on trusted root mismatch", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := testNs

		srcNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer srcNDB.Close()

		srcRoots, err := populateNDB(ctx, srcNDB, ns)
		require.NoError(t, err)

		var buf bytes.Buffer
		exporter, err := newWriteLogExporter(srcNDB, ns, 1, 10, &buf)
		require.NoError(t, err)
		err = exporter.export(ctx)
		require.NoError(t, err)

		badTrustedRoots := map[uint64][]node.Root{
			1: []node.Root{srcRoots[0][0], srcRoots[10][1]},
		}
		badTrustedProvider := newTestTrustedProvider(badTrustedRoots)

		dstNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer dstNDB.Close()

		reader := bytes.NewReader(buf.Bytes())
		importer, err := newWriteLogImporter(dstNDB, ns, badTrustedProvider, 10, reader)
		require.NoError(t, err)
		err = importer.importUntrusted(ctx)
		require.ErrorContains(t, err, "expected root mismatch")
	})

	t.Run("resume from checkpoint", func(t *testing.T) {
		t.Parallel()

		ctx := t.Context()
		ns := testNs

		srcNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer srcNDB.Close()

		srcRoots, err := populateNDB(ctx, srcNDB, ns)
		require.NoError(t, err)
		trustedProvider := newTestTrustedProvider(srcRoots)

		var buf bytes.Buffer
		exporter, err := newWriteLogExporter(srcNDB, ns, 2, 8, &buf)
		require.NoError(t, err)
		err = exporter.export(ctx)
		require.NoError(t, err)

		dstNDB, err := newTestNodeDB(t, ns)
		require.NoError(t, err)
		defer dstNDB.Close()

		cpDir := filepath.Join(t.TempDir())
		require.NoError(t, createCheckpoints(ctx, srcNDB, ns, 5, cpDir))
		require.NoError(t, importCheckpoints(ctx, dstNDB, ns, cpDir))

		reader := bytes.NewReader(buf.Bytes())
		importer, err := newWriteLogImporter(dstNDB, ns, trustedProvider, 7, reader)
		require.NoError(t, err)
		err = importer.importUntrusted(ctx)
		require.NoError(t, err)

		requireSameFinalizedRoots(t, srcNDB, dstNDB, 5, 7)
	})
}

type testTrustedProvider map[uint64]versionRoots

func newTestTrustedProvider(roots map[uint64][]node.Root) testTrustedProvider {
	result := make(testTrustedProvider)
	for version, rootsAtVersion := range roots {
		var vr versionRoots
		for _, root := range rootsAtVersion {
			switch root.Type {
			case node.RootTypeState:
				vr.state = root
			case node.RootTypeIO:
				vr.io = root
			}
		}
		result[version] = vr
	}
	return result
}

func (r testTrustedProvider) roots(_ context.Context, version uint64) (versionRoots, error) {
	roots, ok := r[version]
	if !ok {
		return versionRoots{}, mkvsAPI.ErrVersionNotFound
	}
	return roots, nil
}

func requireSameFinalizedRoots(t *testing.T, srcNDB, dstNDB mkvsAPI.NodeDB, start, end uint64) {
	t.Helper()

	for version := start; version <= end; version++ {
		expectedRoots, err := srcNDB.GetRootsForVersion(version)
		require.NoError(t, err)

		roots, err := dstNDB.GetRootsForVersion(version)
		require.NoError(t, err)
		require.ElementsMatch(t, expectedRoots, roots)
	}
}

func populateNDB(
	ctx context.Context,
	ndb mkvsAPI.NodeDB,
	ns common.Namespace,
) (map[uint64][]node.Root, error) {
	stateTree := mkvs.New(nil, ndb, node.RootTypeState)
	defer stateTree.Close()

	srcRoots := make(map[uint64][]node.Root)

	// Initialize version zero with empty state and IO root.
	version0Roots := []node.Root{
		emptyRoot(ns, 0, node.RootTypeState),
		emptyRoot(ns, 0, node.RootTypeIO),
	}
	if err := ndb.Finalize(version0Roots); err != nil {
		return nil, fmt.Errorf("failed to finalize version 0: %w", err)
	}
	srcRoots[0] = version0Roots

	for version := uint64(1); version <= 10; version++ {
		stateKey := []byte(fmt.Sprintf("state-%d", version))
		stateValue := []byte(fmt.Sprintf("state-value-%d", version))
		if err := stateTree.Insert(ctx, stateKey, stateValue); err != nil {
			return nil, fmt.Errorf("failed to insert state for version %d: %w", version, err)
		}

		_, stateHash, err := stateTree.Commit(ctx, ns, version)
		if err != nil {
			return nil, fmt.Errorf("failed to commit state version %d: %w", version, err)
		}
		stateRoot := node.Root{Namespace: ns, Version: version, Type: node.RootTypeState, Hash: stateHash}

		ioRoot := emptyRoot(ns, version, node.RootTypeIO)
		if version%2 == 0 {
			ioTree := mkvs.New(nil, ndb, node.RootTypeIO) // IO roots are not chained.
			ioKey := []byte(fmt.Sprintf("state-%d", version))
			ioValue := []byte(fmt.Sprintf("state-value-%d", version))
			if err = ioTree.Insert(ctx, ioKey, ioValue); err != nil {
				ioTree.Close()
				return nil, fmt.Errorf("failed to insert io for version %d: %w", version, err)
			}
			_, ioHash, err := ioTree.Commit(ctx, ns, version)
			ioTree.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to commit io version %d: %w", version, err)
			}
			ioRoot = node.Root{Namespace: ns, Version: version, Type: node.RootTypeIO, Hash: ioHash}
		}

		versionRoots := []node.Root{stateRoot, ioRoot}
		if err = ndb.Finalize(versionRoots); err != nil {
			return nil, fmt.Errorf("failed to finalize version %d: %w", version, err)
		}
		srcRoots[version] = versionRoots
	}
	return srcRoots, nil
}
