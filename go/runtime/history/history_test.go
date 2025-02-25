package history

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	err = history.Commit(&blk, true)
	require.Error(err, "Commit should fail for different runtime")

	copy(blk.Block.Header.Namespace[:], runtimeID[:])
	err = history.Commit(&blk, true)
	require.NoError(err, "Commit")

	blk2 := roothash.AnnotatedBlock{
		Height: 40,
		Block:  block.NewGenesisBlock(runtimeID, 0),
	}
	err = history.Commit(&blk2, true)
	require.Error(err, "Commit should fail for lower consensus height")

	putBlk := *blk.Block
	err = history.Commit(&blk, true)
	require.Error(err, "Commit should fail for the same round")
	blk.Block.Header.Round = 5
	err = history.Commit(&blk, true)
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

	ch, sub, err := history.WatchBlocks()
	require.NoError(err)
	defer sub.Close()
	select {
	case blk := <-ch:
		require.EqualValues(blk.Block.Header.Round, lastRound)
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive storage synced round")
	}

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

func TestCommitBatch(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID1 := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)
	runtimeID2 := common.NewTestNamespaceFromSeed([]byte("history test ns 2"), 0)

	prunerFactory := NewNonePrunerFactory()
	history, err := New(runtimeID1, dataDir, prunerFactory, true)
	require.NoError(err, "New")

	require.Equal(runtimeID1, history.RuntimeID())

	// Sample data.
	blk1 := roothash.AnnotatedBlock{
		Height: 1,
		Block:  block.NewGenesisBlock(runtimeID1, 0),
	}
	blk2 := roothash.AnnotatedBlock{
		Height: 3,
		Block:  block.NewGenesisBlock(runtimeID2, 0),
	}
	blk2.Block.Header.Round = 1

	err = history.CommitBatch(nil, true)
	require.NoError(err, "CommitBatch should succeed for empty batch")

	err = history.CommitBatch([]*roothash.AnnotatedBlock{&blk1, &blk2}, true)
	require.Error(err, "CommitBatch should fail when different runtimes IDs")

	copy(blk2.Block.Header.Namespace[:], blk1.Block.Header.Namespace[:])

	// Commit batch in wrong order: round 1 and 0 at consenus height 3 and 1.
	err = history.CommitBatch([]*roothash.AnnotatedBlock{&blk2, &blk1}, true)
	require.Error(err, "CommitBatch should fail for unordered batch")

	// Commit batch round 0 and 1 at consenus height 1 and 3.
	err = history.CommitBatch([]*roothash.AnnotatedBlock{&blk1, &blk2}, true)
	require.NoError(err, "CommitBatch")

	lastHeight, err := history.LastConsensusHeight()
	require.NoError(err, "LastConsensusHeight")
	require.EqualValues(3, lastHeight)

	gotBlock, err := history.GetCommittedBlock(ctx, 0)
	require.NoError(err, "GetCommittedBlock(0)")
	require.Equal(blk1.Block, gotBlock, "GetCommittedBlock should return the correct block")

	gotBlock, err = history.GetCommittedBlock(ctx, roothash.RoundLatest)
	require.NoError(err, "GetCommittedBlock(RoundLatest)")
	require.Equal(blk2.Block, gotBlock, "GetCommittedBlock should return the correct block")

	// Commit for the latest height and round should fail
	err = history.Commit(&blk2, true)
	require.Error(err, "Commit should fail for same consensus height")

	// Commit for the latest round should fail.
	blk2.Height = 4
	err = history.Commit(&blk2, true)
	require.Error(err, "Commit should fail for same round")

	// Commit after batch commit should succeed when round and height increases.
	blk2.Block.Header.Round = 2
	err = history.Commit(&blk2, true)
	require.NoError(err, "Commit")

	err = history.StorageSyncCheckpoint(2)
	require.NoError(err, "StorageSyncCheckpoint should work")

	gotAnnBlk, err := history.GetAnnotatedBlock(ctx, 2)
	require.NoError(err, "GetAnnotatedBlock")
	require.Equal(&blk2, gotAnnBlk, "GetAnnotatedBlock should return the correct block")

	// Try committing another batch after a single commit.
	blk1.Height = 5
	blk2.Height = 7
	blk1.Block.Header.Round = 5
	blk2.Block.Header.Round = 6
	err = history.CommitBatch([]*roothash.AnnotatedBlock{&blk1, &blk2}, false)
	require.NoError(err, "CommitBatch")
}

func testWatchBlocks(t *testing.T, history History, expectedRound uint64) {
	t.Helper()
	require := require.New(t)

	ch, sub, err := history.WatchBlocks()
	require.NoError(err)
	defer sub.Close()
	switch expectedRound {
	case 0:
		// No rounds should be received.
		select {
		case <-ch:
			t.Fatalf("received unexpected round")
		case <-time.After(recvTimeout):
		}
	default:
		select {
		case blk := <-ch:
			require.EqualValues(blk.Block.Header.Round, expectedRound)
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive storage synced round")
		}
	}
}

func TestWatchBlocks(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create a new random temporary directory under /tmp.
	dataDir, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)

	// Sample data
	blk1 := roothash.AnnotatedBlock{
		Height: 40,
		Block:  block.NewGenesisBlock(runtimeID, 0),
	}
	blk1.Block.Header.Round = 10
	blk2 := roothash.AnnotatedBlock{
		Height: 41,
		Block:  block.NewGenesisBlock(runtimeID, 0),
	}
	blk2.Block.Header.Round = 11
	blocks := []*roothash.AnnotatedBlock{&blk1, &blk2}

	// Test history with local storage.
	prunerFactory := NewNonePrunerFactory()
	history, err := New(runtimeID, dataDir, prunerFactory, true)
	require.NoError(err, "New")
	// No blocks should be received.
	testWatchBlocks(t, history, 0)
	// Commit a block and notify.
	err = history.Commit(&blk1, true)
	require.NoError(err, "Commit")
	// No blocks should be received.
	testWatchBlocks(t, history, 0)
	// Commit storage checkpoint.
	err = history.StorageSyncCheckpoint(10)
	require.NoError(err, "StorageSyncCheckpoint")
	// Block should be received.
	testWatchBlocks(t, history, 10)
	// Commit a block without notifying.
	err = history.Commit(&blk2, false)
	require.NoError(err, "Commit")
	err = history.StorageSyncCheckpoint(11)
	require.NoError(err, "StorageSyncCheckpoint")
	// Wait synced round so that notifier processes it.
	_, err = history.WaitRoundSynced(ctx, 11)
	require.NoError(err, "WaitRoundSynced")
	// In case of a local storage, we broadcast blocks when
	// StorageSyncCheckpoint is called, regardless of notify flag.
	testWatchBlocks(t, history, 11)

	// Test history without local storage.
	dataDir2, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir2)
	history, err = New(runtimeID, dataDir2, prunerFactory, false)
	require.NoError(err, "New")
	// No blocks should be received.
	testWatchBlocks(t, history, 0)
	// Commit a block without notifying.
	err = history.Commit(&blk1, false)
	require.NoError(err, "Commit should work")
	// No blocks should be received since commit didn't notify and
	// history has no local storage.
	testWatchBlocks(t, history, 0)
	// Commit a block and also notify.
	err = history.Commit(&blk2, true)
	require.NoError(err, "Commit should work")
	// Block should be received.
	testWatchBlocks(t, history, 11)
	// Wait round sync should return correct round.
	r, err := history.WaitRoundSynced(ctx, 11)
	require.NoError(err, "WaitRoundSynced")
	require.EqualValues(11, r, "WaitRoundSynced")
	// Committing storage checkpoint should panic.
	assert.Panics(t, func() { _ = history.StorageSyncCheckpoint(10) }, "StorageSyncCheckpoint should panic")

	// Test history with local storage and batching.
	dataDir3, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir3)
	history, err = New(runtimeID, dataDir3, prunerFactory, true)
	require.NoError(err, "New")
	testWatchBlocks(t, history, 0)
	// Commit batch without notifying.
	err = history.CommitBatch(blocks, false)
	require.NoError(err, "CommitBatch")
	// In case of a local storage, we broadcast blocks when
	// StorageSyncCheckpoint is called, regardless of notify flag.
	testWatchBlocks(t, history, 0)
	err = history.StorageSyncCheckpoint(10)
	require.NoError(err, "StorageSyncCheckpoint")
	testWatchBlocks(t, history, 10)
	err = history.StorageSyncCheckpoint(11)
	require.NoError(err, "StorageSyncCheckpoint")
	// Wait synced round so that notifier processes it.
	_, err = history.WaitRoundSynced(ctx, 11)
	require.NoError(err, "WaitRoundSynced")
	testWatchBlocks(t, history, 11)

	// Test history without local storage and with batching.
	dataDir4, err := os.MkdirTemp("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir4)
	history, err = New(runtimeID, dataDir4, prunerFactory, false)
	require.NoError(err, "New")
	testWatchBlocks(t, history, 0)
	// Commit batch without notifying.
	err = history.CommitBatch(blocks, false)
	require.NoError(err, "CommitBatch")
	// No block should be received since we set notify to false.
	testWatchBlocks(t, history, 0)
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
	err = history.CommitBatch(blks[:10], false)
	require.NoError(err, "Commit")
	err = history.CommitBatch(blks[10:20], false)
	require.NoError(err, "Commit")
	err = history.CommitBatch(blks[20:30], false)
	require.NoError(err, "Commit")

	// Commit remaining 20 blocks one by one.
	for i := 30; i < n; i++ {
		err = history.Commit(blks[i], true)
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

		err = history.Commit(&blk, true)
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
