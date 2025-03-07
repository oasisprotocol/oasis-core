package history

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"

	"github.com/oasisprotocol/oasis-core/go/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

const recvTimeout = time.Second

func TestHistory(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create a new random temporary directory under /tmp.
	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)
	runtimeID2 := common.NewTestNamespaceFromSeed([]byte("history test ns 2"), 0)

	prunerFactory := NewNonePrunerFactory()
	history, err := New(runtimeID, dataDir, prunerFactory, true)
	require.NoError(err, "New")

	require.Equal(runtimeID, history.RuntimeID())

	lastHeight, err := history.LastConsensusHeight()
	require.NoError(err, "LastConsensusHeight")
	require.EqualValues(0, lastHeight)

	lastRound, err := history.LastStorageSyncedRound()
	require.NoError(err, "LastStorageSyncedRound")
	require.EqualValues(0, lastRound)

	_, err = history.GetBlock(ctx, 10)
	require.Error(err, "GetBlock should fail for non-indexed block")
	require.Equal(roothash.ErrNotFound, err)

	_, err = history.GetAnnotatedBlock(ctx, 10)
	require.Error(err, "GetAnnotatedBlock should fail for non-indexed block")
	require.Equal(roothash.ErrNotFound, err)

	_, err = history.GetBlock(ctx, roothash.RoundLatest)
	require.Error(err, "GetBlock(RoundLatest) should fail for no indexed block")
	require.Equal(roothash.ErrNotFound, err)

	blk := roothash.AnnotatedBlock{
		Height: 50,
		Block:  block.NewGenesisBlock(runtimeID, 0),
	}
	blk.Block.Header.Round = 10

	copy(blk.Block.Header.Namespace[:], runtimeID2[:])
	err = history.Commit([]*roothash.AnnotatedBlock{&blk})
	require.Error(err, "Commit should fail for different runtime")

	copy(blk.Block.Header.Namespace[:], runtimeID[:])
	err = history.Commit([]*roothash.AnnotatedBlock{&blk})
	require.NoError(err, "Commit")

	blk2 := roothash.AnnotatedBlock{
		Height: 40,
		Block:  block.NewGenesisBlock(runtimeID, 0),
	}
	err = history.Commit([]*roothash.AnnotatedBlock{&blk2})
	require.Error(err, "Commit should fail for lower consensus height")

	putBlk := *blk.Block
	err = history.Commit([]*roothash.AnnotatedBlock{&blk})
	require.Error(err, "Commit should fail for the same round")
	blk.Block.Header.Round = 5
	err = history.Commit([]*roothash.AnnotatedBlock{&blk})
	require.Error(err, "Commit should fail for a lower round")
	blk.Block.Header.Round = 10

	lastHeight, err = history.LastConsensusHeight()
	require.NoError(err, "LastConsensusHeight")
	require.EqualValues(50, lastHeight)

	err = history.StorageSyncCheckpoint(12)
	require.Error(err, "StorageSyncCheckpoint should fail for non-indexed round")
	err = history.StorageSyncCheckpoint(10)
	require.NoError(err, "StorageSyncCheckpoint")
	err = history.StorageSyncCheckpoint(5)
	require.Error(err, "StorageSyncCheckpoint should fail for lower height")

	lastRound, err = history.LastStorageSyncedRound()
	require.NoError(err, "LastStorageSyncedRound")
	require.EqualValues(10, lastRound)

	gotBlk, err := history.GetBlock(ctx, 10)
	require.NoError(err, "GetBlock")
	require.Equal(&putBlk, gotBlk, "GetBlock should return the correct block")

	gotAnnBlk, err := history.GetAnnotatedBlock(ctx, 10)
	require.NoError(err, "GetAnnotatedBlock")
	require.Equal(&blk, gotAnnBlk, "GetAnnotatedBlock should return the correct block")

	gotLatestBlk, err := history.GetBlock(ctx, 10)
	require.NoError(err, "GetBlock(RoundLatest)")
	require.Equal(&putBlk, gotLatestBlk, "GetBlock(RoundLatest) should return the correct block")

	// Close history and try to reopen and continue.
	history.Close()

	// Try to manually load the block index database with incorrect runtime ID.
	// Use path from the first runtime.
	_, err = New(runtimeID2, dataDir, prunerFactory, true)
	require.Error(err, "New should return an error on runtime mismatch")

	history, err = New(runtimeID, dataDir, prunerFactory, true)
	require.NoError(err, "New")

	require.Equal(runtimeID, history.RuntimeID())

	// Storage sync checkpoint is not persisted.
	err = history.StorageSyncCheckpoint(10)
	require.NoError(err, "StorageSyncCheckpoint should work")

	lastHeight, err = history.LastConsensusHeight()
	require.NoError(err, "LastConsensusHeight")
	require.EqualValues(50, lastHeight)

	gotBlk, err = history.GetBlock(ctx, 10)
	require.NoError(err, "GetBlock")
	require.Equal(&putBlk, gotBlk, "GetBlock should return the correct block")

	gotAnnBlk, err = history.GetAnnotatedBlock(ctx, 10)
	require.NoError(err, "GetAnnotatedBlock")
	require.Equal(&blk, gotAnnBlk, "GetAnnotatedBlock should return the correct block")

	gotLatestBlk, err = history.GetBlock(ctx, roothash.RoundLatest)
	require.NoError(err, "GetBlock(RoundLatest)")
	require.Equal(&putBlk, gotLatestBlk, "GetBlock(RoundLatest) should return the correct block")
}

func TestCommit(t *testing.T) {
	ctx := t.Context()

	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID1 := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)
	runtimeID2 := common.NewTestNamespaceFromSeed([]byte("history test ns 2"), 0)

	prunerFactory := NewNonePrunerFactory()
	history, err := New(runtimeID1, dataDir, prunerFactory, true)
	require.NoError(t, err, "New")

	blks := createBlocks(runtimeID1)

	t.Run("different runtimes", func(t *testing.T) {
		blks[0].Block.Header.Namespace = runtimeID2
		err = history.Commit(blks)
		require.Error(t, err, "Commit should fail when different runtimes IDs")
		blks[0].Block.Header.Namespace = runtimeID1
	})

	t.Run("wrong order", func(t *testing.T) {
		slices.Reverse(blks)
		err = history.Commit(blks)
		require.Error(t, err, "Commit should fail for unordered batch")
		slices.Reverse(blks)
	})

	t.Run("no blocks", func(t *testing.T) {
		err = history.Commit(nil)
		require.NoError(t, err, "Commit should succeed for empty batch")

		err = history.Commit([]*roothash.AnnotatedBlock{})
		require.NoError(t, err, "Commit should succeed for empty batch")
	})

	t.Run("one block", func(t *testing.T) {
		err = history.Commit(blks[:1])
		require.NoError(t, err, "Commit")

		gotBlock, err := history.GetCommittedBlock(ctx, blks[0].Block.Header.Round)
		require.NoError(t, err, "GetCommittedBlock")
		require.Equal(t, blks[0].Block, gotBlock, "GetCommittedBlock should return the correct block")

		gotBlock, err = history.GetCommittedBlock(ctx, roothash.RoundLatest)
		require.NoError(t, err, "GetCommittedBlock(RoundLatest)")
		require.Equal(t, blks[0].Block, gotBlock, "GetCommittedBlock should return the correct block")

		lastHeight, err := history.LastConsensusHeight()
		require.NoError(t, err, "LastConsensusHeight")
		require.EqualValues(t, blks[0].Height, lastHeight)
	})

	t.Run("multiple blocks", func(t *testing.T) {
		err = history.Commit(blks[1:])
		require.NoError(t, err, "Commit")

		for _, blk := range blks {
			gotBlock, err := history.GetCommittedBlock(ctx, blk.Block.Header.Round)
			require.NoError(t, err, "GetCommittedBlock")
			require.Equal(t, blk.Block, gotBlock, "GetCommittedBlock should return the correct block")
		}

		gotBlock, err := history.GetCommittedBlock(ctx, roothash.RoundLatest)
		require.NoError(t, err, "GetCommittedBlock(RoundLatest)")
		require.Equal(t, blks[len(blks)-1].Block, gotBlock, "GetCommittedBlock should return the correct block")

		lastHeight, err := history.LastConsensusHeight()
		require.NoError(t, err, "LastConsensusHeight")
		require.EqualValues(t, blks[len(blks)-1].Height, lastHeight)
	})

	t.Run("commit at latest height", func(t *testing.T) {
		blk := &roothash.AnnotatedBlock{
			Height: 3,
			Block:  block.NewGenesisBlock(runtimeID1, 0),
		}
		blk.Block.Header.Round = 3
		err = history.Commit([]*roothash.AnnotatedBlock{blk})
		require.Error(t, err, "Commit should fail for same consensus height")
	})

	t.Run("commit at latest round", func(t *testing.T) {
		blk := &roothash.AnnotatedBlock{
			Height: 4,
			Block:  block.NewGenesisBlock(runtimeID1, 0),
		}
		blk.Block.Header.Round = 2
		err = history.Commit([]*roothash.AnnotatedBlock{blk})
		require.Error(t, err, "Commit should fail for same round")
	})
}

func testWatchBlocks(t *testing.T, blkCh <-chan *roothash.AnnotatedBlock, n int) uint64 {
	t.Helper()

	var blk *roothash.AnnotatedBlock
	for i := 0; i < n; i++ {
		select {
		case blk = <-blkCh:
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive storage synced round")
		}
	}
	select {
	case blk = <-blkCh:
		t.Fatalf("received unexpected block: %d", blk.Block.Header.Round)
	case <-time.After(recvTimeout):
	}
	if n == 0 {
		return 0
	}
	return blk.Block.Header.Round
}

func TestWatchBlocksWithHistory(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)
	blks := createBlocks(runtimeID)

	prunerFactory := NewNonePrunerFactory()
	history, err := New(runtimeID, dataDir, prunerFactory, true)
	require.NoError(t, err, "New")

	blkCh, blkSub, err := history.WatchBlocks()
	require.NoError(t, err)
	defer blkSub.Close()

	t.Run("no blocks", func(t *testing.T) {
		_ = testWatchBlocks(t, blkCh, 0)
	})

	t.Run("one block, not initialized", func(t *testing.T) {
		err = history.Commit(blks[:1])
		require.NoError(t, err, "Commit")
		_ = testWatchBlocks(t, blkCh, 0)

		err = history.StorageSyncCheckpoint(blks[0].Block.Header.Round)
		require.NoError(t, err, "StorageSyncCheckpoint")
		_ = testWatchBlocks(t, blkCh, 0)
	})

	err = history.SetInitialized()
	require.NoError(t, err, "SetInitialized")

	t.Run("one block, initialized", func(t *testing.T) {
		err = history.Commit(blks[1:2])
		require.NoError(t, err, "Commit")
		_ = testWatchBlocks(t, blkCh, 0)

		err = history.StorageSyncCheckpoint(blks[1].Block.Header.Round)
		require.NoError(t, err, "StorageSyncCheckpoint")
		round := testWatchBlocks(t, blkCh, 1)
		require.Equal(t, blks[1].Block.Header.Round, round)
	})

	t.Run("multiple blocks, initialized", func(t *testing.T) {
		err = history.Commit(blks[2:])
		require.NoError(t, err, "Commit")
		_ = testWatchBlocks(t, blkCh, 0)

		for _, blk := range blks[2:] {
			err = history.StorageSyncCheckpoint(blk.Block.Header.Round)
			require.NoError(t, err, "StorageSyncCheckpoint")
		}
		round := testWatchBlocks(t, blkCh, len(blks)-2)
		require.Equal(t, blks[len(blks)-1].Block.Header.Round, round)
	})
}

func TestWatchBlocksWithoutHistory(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)
	blks := createBlocks(runtimeID)

	prunerFactory := NewNonePrunerFactory()
	history, err := New(runtimeID, dataDir, prunerFactory, false)
	require.NoError(t, err, "New")

	blkCh, blkSub, err := history.WatchBlocks()
	require.NoError(t, err)
	defer blkSub.Close()

	t.Run("no blocks", func(t *testing.T) {
		testWatchBlocks(t, blkCh, 0)
	})

	t.Run("one block, not initialized", func(t *testing.T) {
		err = history.Commit(blks[:1])
		require.NoError(t, err, "Commit")
		_ = testWatchBlocks(t, blkCh, 0)
	})

	err = history.SetInitialized()
	require.NoError(t, err, "SetInitialized")

	t.Run("one block, initialized", func(t *testing.T) {
		err = history.Commit(blks[1:2])
		require.NoError(t, err, "Commit")
		round := testWatchBlocks(t, blkCh, 1)
		require.Equal(t, blks[1].Block.Header.Round, round)
	})

	t.Run("multiple blocks, initialized", func(t *testing.T) {
		err = history.Commit(blks[2:])
		require.NoError(t, err, "Commit")
		round := testWatchBlocks(t, blkCh, len(blks)-2)
		require.Equal(t, blks[len(blks)-1].Block.Header.Round, round)
	})
}

type testPruneHandler struct {
	done         bool
	doneCh       chan struct{}
	waitRounds   int
	prunedRounds []uint64
	batches      []int
}

func (h *testPruneHandler) Prune(rounds []uint64) error {
	// NOTE: Users must ensure that accessing prunedRounds is safe (e.g., that
	//       no more pruning happens using this handler before prunedRounds is
	//       accessed from a different goroutine).
	if h.done {
		panic("pruned more rounds than specified in waitRounds")
	}

	h.batches = append(h.batches, len(rounds))
	h.prunedRounds = append(h.prunedRounds, rounds...)
	if len(h.prunedRounds) >= h.waitRounds {
		close(h.doneCh)
		h.done = true
	}
	return nil
}

func TestHistoryPrune(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create a new random temporary directory under /tmp.
	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history prune test ns"), 0)

	pruneFactory := NewKeepLastPrunerFactory(10, 100*time.Millisecond)
	history, err := New(runtimeID, dataDir, pruneFactory, true)
	require.NoError(err, "New")
	defer history.Close()

	ph := testPruneHandler{
		doneCh:     make(chan struct{}),
		waitRounds: 41,
	}
	history.Pruner().RegisterHandler(&ph)

	const n = 51

	blks := make([]*roothash.AnnotatedBlock, n)
	for i := 0; i < n; i++ {
		blk := roothash.AnnotatedBlock{
			Height: int64(i),
			Block:  block.NewGenesisBlock(runtimeID, 0),
		}
		blk.Block.Header.Round = uint64(i)
		blks[i] = &blk
	}

	// Commit first 30 blocks in a batch of 10.
	err = history.Commit(blks[:10])
	require.NoError(err, "Commit")
	err = history.Commit(blks[10:20])
	require.NoError(err, "Commit")
	err = history.Commit(blks[20:30])
	require.NoError(err, "Commit")

	// Commit remaining 20 blocks one by one.
	for i := 30; i < n; i++ {
		err = history.Commit([]*roothash.AnnotatedBlock{blks[i]})
		require.NoError(err, "Commit")
	}
	// Simulate storage syncing.
	for i := 0; i < n; i++ {
		err = history.StorageSyncCheckpoint(blks[i].Block.Header.Round)
		require.NoError(err, "StorageSyncCheckpoint")
	}
	// No more blocks after this point.

	// Wait for pruning to complete.
	select {
	case <-ph.doneCh:
	case <-time.After(recvTimeout):
		t.Fatalf("failed to wait for prune to complete")
	}

	// Wait until the pruning transaction has been committed. This is needed because doneCh may be
	// closed before the database transaction commits so the pruning may not yet be visible.
	ctx, cancel := context.WithTimeout(ctx, recvTimeout)
	defer cancel()
	for {
		_, err = history.GetBlock(ctx, 0)
		if err == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		require.Error(err, "GetBlock should fail for pruned block 0")
		require.Equal(roothash.ErrNotFound, err)
		break
	}

	// Ensure we can only lookup the last 10 blocks.
	for i := 0; i < n; i++ {
		_, err = history.GetBlock(ctx, uint64(i))
		if i <= 40 {
			require.Error(err, "GetBlock should fail for pruned block %d", i)
			require.Equal(roothash.ErrNotFound, err)
			continue
		}
		require.NoError(err, "GetBlock(%d)", i)
	}

	// Ensure the prune handler was called.
	require.Len(ph.prunedRounds, 41)
	for i := 0; i <= 40; i++ {
		require.EqualValues(ph.prunedRounds[i], i)
	}
}

type testPruneFailingHandler struct{}

func (h *testPruneFailingHandler) Prune([]uint64) error {
	return fmt.Errorf("thou shall not pass")
}

func TestHistoryPruneError(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create a new random temporary directory under /tmp.
	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history prune error test ns"), 0)

	pruneFactory := NewKeepLastPrunerFactory(10, 100*time.Millisecond)
	history, err := New(runtimeID, dataDir, pruneFactory, true)
	require.NoError(err, "New")
	defer history.Close()

	var ph testPruneFailingHandler
	history.Pruner().RegisterHandler(&ph)

	// Create some blocks.
	for i := 0; i <= 50; i++ {
		blk := roothash.AnnotatedBlock{
			Height: int64(i),
			Block:  block.NewGenesisBlock(runtimeID, 0),
		}
		blk.Block.Header.Round = uint64(i)

		err = history.Commit([]*roothash.AnnotatedBlock{&blk})
		require.NoError(err, "Commit")

		err = history.StorageSyncCheckpoint(blk.Block.Header.Round)
		require.NoError(err, "StorageSyncCheckpoint")
	}

	// Wait for some pruning.
	time.Sleep(200 * time.Millisecond)

	// Ensure nothing was pruned.
	for i := 0; i <= 50; i++ {
		_, err = history.GetBlock(ctx, uint64(i))
		require.NoError(err, "GetBlock(%d)", i)
	}
}

func createBlocks(runtimeID common.Namespace) []*roothash.AnnotatedBlock {
	blks := []*roothash.AnnotatedBlock{
		{
			Height: 1,
			Block:  block.NewGenesisBlock(runtimeID, 0),
		},
		{
			Height: 3,
			Block:  block.NewGenesisBlock(runtimeID, 0),
		},
		{
			Height: 4,
			Block:  block.NewGenesisBlock(runtimeID, 0),
		},
		{
			Height: 6,
			Block:  block.NewGenesisBlock(runtimeID, 0),
		},
	}
	for i, blk := range blks {
		blk.Block.Header.Round = uint64(i) + 1
	}
	return blks
}
