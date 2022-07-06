package history

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

const recvTimeout = 1 * time.Second

func TestHistory(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create a new random temporary directory under /tmp.
	dataDir, err := ioutil.TempDir("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)
	runtimeID2 := common.NewTestNamespaceFromSeed([]byte("history test ns 2"), 0)

	history, err := New(dataDir, runtimeID, NewDefaultConfig(), true)
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

	err = history.ConsensusCheckpoint(42)
	require.NoError(err, "ConsensusCheckpoint")
	err = history.ConsensusCheckpoint(40)
	require.Error(err, "ConsensusCheckpoint should fail for lower height")

	lastHeight, err = history.LastConsensusHeight()
	require.NoError(err, "LastConsensusHeight")
	require.EqualValues(42, lastHeight)

	blk := roothash.AnnotatedBlock{
		Height: 40,
		Block:  block.NewGenesisBlock(runtimeID, 0),
	}
	blk.Block.Header.Round = 10

	roundResults := &roothash.RoundResults{
		Messages: []*roothash.MessageEvent{
			{Module: "", Code: 0, Index: 0},
			{Module: "", Code: 0, Index: 1},
		},
	}

	err = history.Commit(&blk, roundResults, true)
	require.Error(err, "Commit should fail for lower consensus height")

	blk.Height = 50
	copy(blk.Block.Header.Namespace[:], runtimeID2[:])
	err = history.Commit(&blk, roundResults, true)
	require.Error(err, "Commit should fail for different runtime")

	copy(blk.Block.Header.Namespace[:], runtimeID[:])
	err = history.Commit(&blk, roundResults, true)
	require.NoError(err, "Commit")
	putBlk := *blk.Block
	err = history.Commit(&blk, roundResults, true)
	require.Error(err, "Commit should fail for the same round")
	blk.Block.Header.Round = 5
	err = history.Commit(&blk, roundResults, true)
	require.Error(err, "Commit should fail for a lower round")
	blk.Block.Header.Round = 10

	lastHeight, err = history.LastConsensusHeight()
	require.NoError(err, "LastConsensusHeight")
	require.EqualValues(50, lastHeight)

	err = history.StorageSyncCheckpoint(ctx, 12)
	require.Error(err, "StorageSyncCheckpoint should fail for non-indexed round")
	err = history.StorageSyncCheckpoint(ctx, 10)
	require.NoError(err, "StorageSyncCheckpoint")
	err = history.StorageSyncCheckpoint(ctx, 5)
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

	gotResults, err := history.GetRoundResults(ctx, 10)
	require.NoError(err, "GetRoundResults")
	require.Equal(roundResults, gotResults, "GetRoundResults should return the correct results")

	// Close history and try to reopen and continue.
	history.Close()

	// Try to manually load the block index database with incorrect runtime ID.
	// Use path from the first runtime.
	_, err = New(dataDir, runtimeID2, NewDefaultConfig(), true)
	require.Error(err, "New should return an error on runtime mismatch")

	history, err = New(dataDir, runtimeID, NewDefaultConfig(), true)
	require.NoError(err, "New")

	require.Equal(runtimeID, history.RuntimeID())

	// Storage sync checkpoint is not persisted.
	err = history.StorageSyncCheckpoint(ctx, 10)
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

	gotResults, err = history.GetRoundResults(ctx, 10)
	require.NoError(err, "GetRoundResults")
	require.Equal(roundResults, gotResults, "GetRoundResults should return the correct results")
}

func testWatchBlocks(t *testing.T, history History, expectedRound uint64) {
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
	dataDir, err := ioutil.TempDir("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history test ns 1"), 0)

	// Test history with local storage.
	history, err := New(dataDir, runtimeID, NewDefaultConfig(), true)
	require.NoError(err, "New")
	// No blocks should be received.
	testWatchBlocks(t, history, 0)

	// Commit a block.
	err = history.ConsensusCheckpoint(40)
	require.NoError(err, "ConsensusCheckpoint")
	blk := roothash.AnnotatedBlock{
		Height: 40,
		Block:  block.NewGenesisBlock(runtimeID, 0),
	}
	blk.Block.Header.Round = 10
	roundResults := &roothash.RoundResults{
		Messages: []*roothash.MessageEvent{
			{Module: "", Code: 0, Index: 0},
			{Module: "", Code: 0, Index: 1},
		},
	}
	err = history.Commit(&blk, roundResults, true)
	require.NoError(err, "Commit")

	// No blocks should be received.
	testWatchBlocks(t, history, 0)

	// Commit storage checkpoint.
	err = history.StorageSyncCheckpoint(ctx, 10)
	require.NoError(err, "StorageSyncCheckpoint")

	// Block should be received.
	testWatchBlocks(t, history, 10)

	// Test history without local storage.
	dataDir2, err := ioutil.TempDir("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir2)
	history, err = New(dataDir2, runtimeID, NewDefaultConfig(), false)
	require.NoError(err, "New")
	// No blocks should be received.
	testWatchBlocks(t, history, 0)

	// Commit a block.
	err = history.ConsensusCheckpoint(40)
	require.NoError(err, "ConsensusCheckpoint")
	err = history.Commit(&blk, roundResults, true)
	require.NoError(err, "Commit should work")

	// Block should be received.
	testWatchBlocks(t, history, 10)

	// Wait round sync should return correct round.
	r, err := history.WaitRoundSynced(ctx, 10)
	require.NoError(err, "WaitRoundSynced")
	require.EqualValues(10, r, "WaitRoundSynced")

	// Committing storage checkpoint should panic.
	assert.Panics(t, func() { _ = history.StorageSyncCheckpoint(ctx, 10) }, "StorageSyncCheckpoint should panic")
}

type testPruneHandler struct {
	done         bool
	doneCh       chan struct{}
	waitRounds   int
	prunedRounds []uint64
	batches      []int
}

func (h *testPruneHandler) Prune(ctx context.Context, rounds []uint64) error {
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
	dataDir, err := ioutil.TempDir("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history prune test ns"), 0)

	history, err := New(dataDir, runtimeID, &Config{
		Pruner:        NewKeepLastPruner(10),
		PruneInterval: 100 * time.Millisecond,
	}, true)
	require.NoError(err, "New")
	defer history.Close()

	ph := testPruneHandler{
		doneCh:     make(chan struct{}),
		waitRounds: 41,
	}
	history.Pruner().RegisterHandler(&ph)

	// Create some blocks.
	for i := 0; i <= 50; i++ {
		blk := roothash.AnnotatedBlock{
			Height: int64(i),
			Block:  block.NewGenesisBlock(runtimeID, 0),
		}
		blk.Block.Header.Round = uint64(i)

		var msgResults []*roothash.MessageEvent
		if i%5 == 0 {
			msgResults = []*roothash.MessageEvent{
				{Module: "", Code: 0, Index: 0},
				{Module: "", Code: 0, Index: 1},
			}
		}

		roundResults := &roothash.RoundResults{
			Messages: msgResults,
		}

		err = history.Commit(&blk, roundResults, true)
		require.NoError(err, "Commit")

		err = history.StorageSyncCheckpoint(ctx, blk.Block.Header.Round)
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
	for i := 0; i <= 50; i++ {
		_, err = history.GetBlock(ctx, uint64(i))
		if i <= 40 {
			require.Error(err, "GetBlock should fail for pruned block %d", i)
			require.Equal(roothash.ErrNotFound, err)
		} else {
			require.NoError(err, "GetBlock(%d)", i)
		}

		roundResults, err := history.GetRoundResults(ctx, uint64(i))
		if i <= 40 {
			require.Error(err, "GetRoundResults(%d)", i)
			require.Equal(roothash.ErrNotFound, err)
		} else if i%5 == 0 {
			require.NoError(err, "GetRoundResults(%d)", i)
			require.NotEmpty(roundResults.Messages, "GetRoundResults should return correct results for block %d", i)
		}
	}

	// Ensure the prune handler was called.
	require.Len(ph.prunedRounds, 41)
	for i := 0; i <= 40; i++ {
		require.EqualValues(ph.prunedRounds[i], i)
	}
}

type testPruneFailingHandler struct{}

func (h *testPruneFailingHandler) Prune(ctx context.Context, rounds []uint64) error {
	return fmt.Errorf("thou shall not pass")
}

func TestHistoryPruneError(t *testing.T) {
	require := require.New(t)
	ctx := context.Background()

	// Create a new random temporary directory under /tmp.
	dataDir, err := ioutil.TempDir("", "oasis-runtime-history-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	runtimeID := common.NewTestNamespaceFromSeed([]byte("history prune error test ns"), 0)

	history, err := New(dataDir, runtimeID, &Config{
		Pruner:        NewKeepLastPruner(10),
		PruneInterval: 100 * time.Millisecond,
	}, true)
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

		err = history.Commit(&blk, nil, true)
		require.NoError(err, "Commit")

		err = history.StorageSyncCheckpoint(ctx, blk.Block.Header.Round)
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
