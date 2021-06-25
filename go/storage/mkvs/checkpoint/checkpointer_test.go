package checkpoint

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	badgerDb "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	testCheckInterval = 50 * time.Millisecond
	testNumKept       = 2
)

func testCheckpointer(t *testing.T, earliestVersion, interval uint64, preExistingData bool) {
	require := require.New(t)
	ctx := context.Background()

	// Initialize a database.
	dir, err := ioutil.TempDir("", "mkvs.checkpointer")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dir)

	ndb, err := badgerDb.New(&db.Config{
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

			err = ndb.Finalize(ctx, []node.Root{root})
			require.NoError(err, "Finalize")
		}
	} else {
		root.Version = earliestVersion
	}

	// Create a file-based checkpoint creator.
	fc, err := NewFileCreator(filepath.Join(dir, "checkpoints"), ndb)
	require.NoError(err, "NewFileCreator")

	// Create a checkpointer.
	cp, err := NewCheckpointer(ctx, ndb, fc, CheckpointerConfig{
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
		GetRoots: func(ctx context.Context, version uint64) ([]node.Root, error) {
			if version < earliestVersion {
				// Simulate early block fetch failing.
				return nil, fmt.Errorf("version not found")
			}
			return ndb.GetRootsForVersion(ctx, version)
		},
	})
	require.NoError(err, "NewCheckpointer")

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

		err = ndb.Finalize(ctx, []node.Root{root})
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
				Version:   checkpointVersion,
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
			Version:   checkpointVersion,
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
	t.Run("Basic", func(t *testing.T) {
		testCheckpointer(t, 0, 1, false)
	})
	t.Run("NonZeroEarliestVersion", func(t *testing.T) {
		testCheckpointer(t, 1000, 1, false)
	})
	t.Run("NonZeroEarliestInitialVersion", func(t *testing.T) {
		testCheckpointer(t, 100, 1, true)
	})
	t.Run("MaybeUnderflow", func(t *testing.T) {
		testCheckpointer(t, 5, 10, true)
	})
	t.Run("ForceCheckpoint", func(t *testing.T) {
		testCheckpointer(t, 0, 10, false)
	})
}
