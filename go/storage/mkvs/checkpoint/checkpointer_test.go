package checkpoint

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db"
	dbApi "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	dbTesting "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/testing"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	testCheckInterval = 50 * time.Millisecond
	testNumKept       = 2
)

func testCheckpointer(t *testing.T, factory dbApi.Factory, earliestVersion, interval uint64, preExistingData bool) {
	require := require.New(t)

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// Initialize a database.
	dir, err := os.MkdirTemp("", "mkvs.checkpointer")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	ndb, err := factory.New(&dbApi.Config{
		DB:           filepath.Join(dir, "db"),
		Namespace:    testNs,
		MaxCacheSize: 16 * 1024 * 1024,
	})
	require.NoError(err, "New")

	var root node.Root
	root.Empty()
	root.Namespace = testNs
	root.Type = node.RootTypeState

	if preExistingData && earliestVersion > 0 {
		// Create some pre-existing roots in the database.
		for round := uint64(0); round < earliestVersion; round++ {
			tree := mkvs.NewWithRoot(nil, ndb, root)
			err = tree.Insert(ctx, []byte(fmt.Sprintf("round %d", round)), []byte(fmt.Sprintf("value %d", round)))
			require.NoError(err, "Insert")

			var rootHash hash.Hash
			_, rootHash, err = tree.Commit(ctx, testNs, round)
			require.NoError(err, "Commit")

			root.Version = round
			root.Hash = rootHash

			err = ndb.Finalize([]node.Root{root})
			require.NoError(err, "Finalize")
		}
	} else {
		root.Version = earliestVersion
	}

	// Create a file-based checkpoint creator.
	fc, err := NewFileCreator(filepath.Join(dir, "checkpoints"), ndb)
	require.NoError(err, "NewFileCreator")

	// Create and run a checkpointer.
	cp := NewCheckpointer(ndb, fc, CheckpointerConfig{
		Name:            "test",
		Namespace:       testNs,
		CheckInterval:   testCheckInterval,
		RootsPerVersion: 1,
		Parameters: &CreationParameters{
			Interval:       interval,
			NumKept:        testNumKept,
			ChunkSize:      16 * 1024,
			InitialVersion: earliestVersion,
		},
		GetRoots: func(_ context.Context, version uint64) ([]node.Root, error) {
			if version < earliestVersion {
				// Simulate early block fetch failing.
				return nil, fmt.Errorf("version not found")
			}
			return ndb.GetRootsForVersion(version)
		},
	})
	wg.Go(func() {
		err := cp.Serve(ctx)
		if err != context.Canceled {
			require.NoError(err)
		}
	})

	// Start watching checkpoints.
	cpCh, sub, err := cp.WatchCheckpoints()
	require.NoError(err, "WatchCheckpoints")
	defer sub.Close()

	// Finalize a few rounds.
	var round uint64
	for round = earliestVersion; round < earliestVersion+(testNumKept+1)*interval; round++ {
		tree := mkvs.NewWithRoot(nil, ndb, root)
		err = tree.Insert(ctx, []byte(fmt.Sprintf("round %d", round)), []byte(fmt.Sprintf("value %d", round)))
		require.NoError(err, "Insert")

		_, rootHash, err := tree.Commit(ctx, testNs, round)
		require.NoError(err, "Commit")

		root.Version = round
		root.Hash = rootHash

		err = ndb.Finalize([]node.Root{root})
		require.NoError(err, "Finalize")
		cp.NotifyNewVersion(round)

		select {
		case <-cp.(*checkpointer).statusCh:
		case <-time.After(2 * testCheckInterval):
			t.Fatalf("failed to wait for checkpointer to checkpoint")
		}

		// Make sure that there are always the correct number of checkpoints.
		if round > earliestVersion+(testNumKept+1)*interval {
			cps, err := fc.GetCheckpoints(ctx, &GetCheckpointsRequest{
				Version:   v1,
				Namespace: testNs,
			})
			require.NoError(err, "GetCheckpoints")
			require.Len(cps, testNumKept, "incorrect number of live checkpoints")

			// Make sure checkpoint event was emitted.
			select {
			case v := <-cpCh:
				require.Equal(cps[len(cps)-1].Root.Version, v, "checkpoint event should be correct")
			case <-time.After(2 * testCheckInterval):
				t.Fatalf("failed to wait for checkpointer to emit event")
			}
		}
	}

	// Force a checkpoint at a version outside the regular interval.
	if interval > 1 {
		cpVersion := round - interval + 1
		cp.ForceCheckpoint(cpVersion)

		select {
		case <-cp.(*checkpointer).statusCh:
		case <-time.After(2 * testCheckInterval):
			t.Fatalf("failed to wait for checkpointer to checkpoint")
		}

		// Make sure that the correct checkpoint was created.
		cps, err := fc.GetCheckpoints(ctx, &GetCheckpointsRequest{
			Version:   v1,
			Namespace: testNs,
		})
		require.NoError(err, "GetCheckpoints")

		var found bool
		for _, cpm := range cps {
			if cpm.Root.Version == cpVersion {
				found = true
				break
			}
		}
		require.True(found, "forced checkpoint should have been created")
	}
}

func TestCheckpointer(t *testing.T) {
	dbTesting.TestMultipleBackends(t, db.Backends, testCheckpointerWithBackend)
}

func testCheckpointerWithBackend(t *testing.T, factory dbApi.Factory) {
	t.Run("Basic", func(t *testing.T) {
		testCheckpointer(t, factory, 0, 1, false)
	})
	t.Run("NonZeroEarliestVersion", func(t *testing.T) {
		testCheckpointer(t, factory, 1000, 1, false)
	})
	t.Run("NonZeroEarliestInitialVersion", func(t *testing.T) {
		testCheckpointer(t, factory, 100, 1, true)
	})
	t.Run("MaybeUnderflow", func(t *testing.T) {
		testCheckpointer(t, factory, 5, 10, true)
	})
	t.Run("ForceCheckpoint", func(t *testing.T) {
		testCheckpointer(t, factory, 0, 10, false)
	})
}
