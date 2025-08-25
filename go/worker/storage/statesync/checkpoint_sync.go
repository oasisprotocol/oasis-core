package statesync

import (
	"bytes"
	"cmp"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/checkpointsync"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/synclegacy"
)

const (
	// cpListsTimeout is the timeout for fetching checkpoints from all nodes.
	cpListsTimeout = 30 * time.Second

	// cpRestoreChunkTimeout is the timeout for restoring a checkpoint chunk from the remote peer.
	cpRestoreChunkTimeout = 60 * time.Second

	// cpRestoreTimeout is the timeout for restoring the whole checkpoint from the remote peers.
	//
	// As of now it takes ~10-30 min to restore the state from the checkpoint, however the timeout
	// should be significantly higher to account for the growing state.
	cpRestoreTimeout = 12 * time.Hour

	checkpointStatusDone = 0
	checkpointStatusNext = 1
	checkpointStatusBail = 2

	// LogEventCheckpointSyncSuccess is a log event value that signals that checkpoint sync was successful.
	LogEventCheckpointSyncSuccess = "worker/storage/checkpoint-sync-success"
)

// ErrNoUsableCheckpoints is the error returned when none of the checkpoints could be synced.
var ErrNoUsableCheckpoints = errors.New("storage: no checkpoint could be synced")

// CheckpointSyncConfig is the checkpoint sync configuration.
type CheckpointSyncConfig struct {
	// Disabled specifies whether checkpoint sync should be disabled. In this case the state sync worker will
	// only sync by applying all diffs from genesis.
	Disabled bool

	// ChunkFetcherCount specifies the number of parallel checkpoint chunk fetchers.
	ChunkFetcherCount uint
}

// Validate performs configuration checks.
func (cfg *CheckpointSyncConfig) Validate() error {
	if !cfg.Disabled && cfg.ChunkFetcherCount == 0 {
		return fmt.Errorf("number of checkpoint chunk fetchers must be greater than zero")
	}
	return nil
}

type chunk struct {
	*checkpoint.ChunkMetadata

	// checkpoint points to the checkpoint this chunk originated from.
	checkpoint *checkpointsync.Checkpoint
}

type chunkHeap struct {
	array  []*chunk
	length int
}

func (h chunkHeap) Len() int           { return h.length }
func (h chunkHeap) Less(i, j int) bool { return h.array[i].Index < h.array[j].Index }
func (h chunkHeap) Swap(i, j int)      { h.array[i], h.array[j] = h.array[j], h.array[i] }

func (h *chunkHeap) Push(x any) {
	h.array[h.length] = x.(*chunk)
	h.length++
}

func (h *chunkHeap) Pop() any {
	h.length--
	ret := h.array[h.length]
	h.array[h.length] = nil
	return ret
}

func (w *Worker) checkpointChunkFetcher(
	ctx context.Context,
	chunkDispatchCh chan *chunk,
	chunkReturnCh chan *chunk,
	errorCh chan int,
) {
	for {
		var chunk *chunk
		var ok bool
		select {
		case <-ctx.Done():
			return
		case chunk, ok = <-chunkDispatchCh:
			if !ok {
				return
			}
		}

		chunkCtx, cancel := context.WithTimeout(ctx, cpRestoreChunkTimeout)
		defer cancel()

		// Fetch chunk from peers.
		rsp, pf, err := w.fetchChunk(chunkCtx, chunk)
		if err != nil {
			w.logger.Error("failed to fetch chunk from peers",
				"err", err,
				"chunk", chunk.Index,
			)
			chunkReturnCh <- chunk
			continue
		}

		// Restore fetched chunk.
		done, err := w.localStorage.Checkpointer().RestoreChunk(chunkCtx, chunk.Index, bytes.NewBuffer(rsp))
		cancel()

		switch {
		case done:
			pf.RecordSuccess()
			// Signal to the toplevel handler that we're done.
			chunkReturnCh <- nil
			return
		case err != nil:
			w.logger.Error("chunk restoration failed",
				"chunk", chunk.Index,
				"root", chunk.Root,
				"err", err,
			)

			switch {
			case errors.Is(err, checkpoint.ErrChunkCorrupted):
				pf.RecordFailure()
				chunkReturnCh <- chunk
			case errors.Is(err, checkpoint.ErrChunkProofVerificationFailed):
				pf.RecordBadPeer()

				// Also punish all peers that advertised this checkpoint.
				for _, cpPeer := range chunk.checkpoint.Peers {
					cpPeer.RecordBadPeer()
				}

				errorCh <- checkpointStatusNext
				return
			default:
				errorCh <- checkpointStatusBail
				return
			}
		default:
			pf.RecordSuccess()
		}
	}
}

// fetchChunk fetches chunk using checkpoint sync p2p protocol client.
//
// In case of no peers or error, it fallbacks to the legacy storage sync protocol.
func (w *Worker) fetchChunk(ctx context.Context, chunk *chunk) ([]byte, rpc.PeerFeedback, error) {
	rsp1, pf, err := w.checkpointSync.GetCheckpointChunk(
		ctx,
		&checkpointsync.GetCheckpointChunkRequest{
			Version: chunk.Version,
			Root:    chunk.Root,
			Index:   chunk.Index,
			Digest:  chunk.Digest,
		},
		&checkpointsync.Checkpoint{
			Metadata: chunk.checkpoint.Metadata,
			Peers:    chunk.checkpoint.Peers,
		},
	)
	if err == nil { // if NO error
		return rsp1.Chunk, pf, nil
	}

	rsp2, pf, err := w.legacyStorageSync.GetCheckpointChunk(
		ctx,
		&synclegacy.GetCheckpointChunkRequest{
			Version: chunk.Version,
			Root:    chunk.Root,
			Index:   chunk.Index,
			Digest:  chunk.Digest,
		},
		&synclegacy.Checkpoint{
			Metadata: chunk.checkpoint.Metadata,
			Peers:    chunk.checkpoint.Peers,
		},
	)
	if err != nil {
		return nil, nil, err
	}
	return rsp2.Chunk, pf, nil
}

func (w *Worker) handleCheckpoint(ctx context.Context, check *checkpointsync.Checkpoint, maxParallelRequests uint) (cpStatus int, rerr error) {
	ctx, cancel := context.WithTimeout(ctx, cpRestoreTimeout)
	defer cancel()
	if err := w.localStorage.Checkpointer().StartRestore(ctx, check.Metadata); err != nil {
		// Any previous restores were already aborted by the driver up the call stack, so
		// things should have been going smoothly here; bail.
		return checkpointStatusBail, fmt.Errorf("can't start checkpoint restore: %w", err)
	}
	// This defer has to be here so that we're sure no workers are running anymore during
	// any potential aborts.
	defer func() {
		if cpStatus == checkpointStatusDone {
			return
		}
		// Abort has to succeed even if we were interrupted by context cancellation.
		ctx := context.Background()
		if err := w.localStorage.Checkpointer().AbortRestore(ctx); err != nil {
			cpStatus = checkpointStatusBail
			w.logger.Error("error while aborting checkpoint restore on handler exit, aborting sync",
				"err", err,
			)
		}
	}()

	chunkDispatchCh := make(chan *chunk)
	defer close(chunkDispatchCh)

	chunkReturnCh := make(chan *chunk, maxParallelRequests)
	errorCh := make(chan int, maxParallelRequests)

	chunkCtx, cancel := context.WithCancel(ctx)

	// Spawn the worker group to fetch and restore checkpoint chunks.
	var workerGroup sync.WaitGroup
	doneCh := make(chan any)
	for i := uint(0); i < maxParallelRequests; i++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			w.checkpointChunkFetcher(chunkCtx, chunkDispatchCh, chunkReturnCh, errorCh)
		}()
	}
	go func() {
		defer close(doneCh)
		workerGroup.Wait()
	}()

	// Cancel on exit and wait for the worker pool to drain so that the abort
	// above can proceed safely.
	defer func() {
		cancel()
		<-doneCh
	}()

	// Prepare the heap of chunks.
	chunks := &chunkHeap{
		array:  make([]*chunk, len(check.Chunks)),
		length: 0,
	}
	heap.Init(chunks)

	for i, c := range check.Chunks {
		heap.Push(chunks, &chunk{
			ChunkMetadata: &checkpoint.ChunkMetadata{
				Version: check.Version,
				Index:   uint64(i),
				Digest:  c,
				Root:    check.Root,
			},
			checkpoint: check,
		})
	}
	w.logger.Debug("checkpoint chunks prepared for dispatch",
		"chunks", len(check.Chunks),
		"checkpoint_root", check.Root,
	)

	// Feed the workers with chunks.
	var next *chunk
	var outChan chan *chunk

	for {
		if chunks.length == 0 {
			next = nil
			outChan = nil
		} else {
			next = heap.Pop(chunks).(*chunk)
			outChan = chunkDispatchCh
		}

		select {
		case <-ctx.Done():
			return checkpointStatusBail, ctx.Err()

		case returned := <-chunkReturnCh:
			if returned == nil {
				// Restoration completed, no more chunks.
				return checkpointStatusDone, nil
			}
			// TODO: Per-chunk backoff?
			heap.Push(chunks, returned)

		case status := <-errorCh:
			return status, nil

		// If there's no chunk to send, outChan will be nil here, blocking forever. We still need to wait
		// for other events even if there's no chunk to dispatch, since they may simply all be in processing.
		case outChan <- next:
			next = nil

		case <-doneCh:
			// No usable workers left, move on to the next checkpoint.
			return checkpointStatusNext, fmt.Errorf("no usable workers")
		}

		if next != nil {
			heap.Push(chunks, next)
		}
	}
}

func (w *Worker) getCheckpointList(ctx context.Context) ([]*checkpointsync.Checkpoint, error) {
	ctx, cancel := context.WithTimeout(ctx, cpListsTimeout)
	defer cancel()

	list, err := w.fetchCheckpoints(ctx)
	if err != nil {
		w.logger.Error("failed to retrieve any checkpoints",
			"err", err,
		)
		return nil, err
	}

	// Sort checkpoints by version, then by number of peers, descending.
	sortCheckpoints(list)

	return list, nil
}

// fetchCheckpoints fetches checkpoints using checkpoint sync p2p protocol client.
//
// In case of no peers, error or no checkpoints, it fallbacks to the legacy storage sync protocol.
func (w *Worker) fetchCheckpoints(ctx context.Context) ([]*checkpointsync.Checkpoint, error) {
	list1, err := w.checkpointSync.GetCheckpoints(ctx, &checkpointsync.GetCheckpointsRequest{
		Version: 1,
	})
	if err == nil && len(list1) > 0 { // if NO error and at least one checkpoint
		return list1, nil
	}

	list2, err := w.legacyStorageSync.GetCheckpoints(ctx, &synclegacy.GetCheckpointsRequest{
		Version: 1,
	})
	if err != nil {
		return nil, err
	}
	var cps []*checkpointsync.Checkpoint
	for _, cp := range list2 {
		cps = append(cps, &checkpointsync.Checkpoint{
			Metadata: cp.Metadata,
			Peers:    cp.Peers,
		})
	}
	return cps, nil
}

// sortCheckpoints sorts the slice in-place (descending by version, peers, hash).
func sortCheckpoints(s []*checkpointsync.Checkpoint) {
	slices.SortFunc(s, func(a, b *checkpointsync.Checkpoint) int {
		return cmp.Or(
			cmp.Compare(b.Root.Version, a.Root.Version),
			cmp.Compare(len(b.Peers), len(a.Peers)),
			bytes.Compare(b.Root.Hash[:], a.Root.Hash[:]),
		)
	})
}

func (w *Worker) checkCheckpointUsable(ctx context.Context, cp *checkpointsync.Checkpoint, remainingMask outstandingMask, genesisRound uint64) bool {
	namespace := w.commonNode.Runtime.ID()
	if !namespace.Equal(&cp.Root.Namespace) {
		// Not for the right runtime.
		return false
	}
	if cp.Root.Version == genesisRound && cp.Root.Type == storageApi.RootTypeIO {
		// Never fetch i/o root for genesis round.
		return false
	}

	blk, err := w.commonNode.Runtime.History().GetCommittedBlock(ctx, cp.Root.Version)
	if err != nil {
		w.logger.Error("can't get block information for checkpoint, skipping", "err", err, "root", cp.Root)
		return false
	}
	_, lastIORoot, lastStateRoot := w.GetLastSynced()
	lastVersions := map[storageApi.RootType]uint64{
		storageApi.RootTypeIO:    lastIORoot.Version,
		storageApi.RootTypeState: lastStateRoot.Version,
	}
	if namespace.Equal(&blk.Header.Namespace) {
		for _, root := range blk.Header.StorageRoots() {
			if cp.Root.Type == root.Type && root.Hash.Equal(&cp.Root.Hash) {
				// Do we already have this root?
				if lastVersions[cp.Root.Type] < cp.Root.Version && remainingMask.contains(cp.Root.Type) {
					return true
				}
				return false
			}
		}
	}
	w.logger.Info("checkpoint for unknown root skipped", "root", cp.Root)
	return false
}

func (w *Worker) syncCheckpoints(ctx context.Context, genesisRound uint64, wantOnlyGenesis bool) (*blockSummary, error) {
	// Store roots and round info for checkpoints that finished syncing.
	// Round and namespace info will get overwritten as rounds are skipped
	// for errors, driven by remainingRoots.
	var syncState blockSummary

	// Fetch checkpoints from peers.
	cps, err := w.getCheckpointList(ctx)
	if err != nil {
		return nil, fmt.Errorf("can't get checkpoint list from peers: %w", err)
	}

	// If we only want the genesis checkpoint, filter it out.
	if wantOnlyGenesis && len(cps) > 0 {
		var filteredCps []*checkpointsync.Checkpoint
		for _, cp := range cps {
			if cp.Root.Version == genesisRound {
				filteredCps = append(filteredCps, cp)
			}
		}
		cps = filteredCps
	}

	// Try all the checkpoints now, from most recent backwards.
	var (
		prevVersion      = ^uint64(0)
		multipartRunning bool
		mask             outstandingMask
	)
	remainingRoots := outstandingMaskFull

	defer func() {
		if !multipartRunning {
			return
		}
		if err := w.localStorage.NodeDB().AbortMultipartInsert(); err != nil {
			w.logger.Error("error aborting multipart restore on exit from syncer",
				"err", err,
			)
		}
	}()

	for _, check := range cps {

		if check.Root.Version < genesisRound || !w.checkCheckpointUsable(ctx, check, remainingRoots, genesisRound) {
			continue
		}

		if check.Root.Version != prevVersion {
			// Starting a new round, so we need to clean up all state from
			// previous retries. Aborting multipart works with no multipart in
			// progress too.
			multipartRunning = false
			if err := w.localStorage.NodeDB().AbortMultipartInsert(); err != nil {
				return nil, fmt.Errorf("error aborting previous multipart restore: %w", err)
			}
			if err := w.localStorage.NodeDB().StartMultipartInsert(check.Root.Version); err != nil {
				return nil, fmt.Errorf("error starting multipart insert for round %d: %w", check.Root.Version, err)
			}
			multipartRunning = true
			remainingRoots = outstandingMaskFull
			prevVersion = check.Root.Version
			syncState.Roots = nil

			if check.Root.Version == genesisRound {
				// Genesis round has no i/o root. The remote node could have
				// (an invalid) one checkpointed, if its history state was not
				// cleared during a dump-restore upgrade. Ignore fetching it and
				// use an empty i/o root.
				remainingRoots.remove(storageApi.RootTypeIO)

				root := storageApi.Root{
					Namespace: check.Root.Namespace,
					Version:   check.Root.Version,
					Type:      storageApi.RootTypeIO,
				}
				root.Hash.Empty()
				syncState.Roots = append(syncState.Roots, root)
			}
		}

		status, err := w.handleCheckpoint(ctx, check, w.checkpointSyncCfg.ChunkFetcherCount)
		switch status {
		case checkpointStatusDone:
			w.logger.Info("successfully restored from checkpoint", "root", check.Root, "mask", mask)

			syncState.Namespace = check.Root.Namespace
			syncState.Round = check.Root.Version
			syncState.Roots = append(syncState.Roots, check.Root)
			remainingRoots.remove(check.Root.Type)
			if remainingRoots.isEmpty() {
				if err = w.localStorage.NodeDB().Finalize(syncState.Roots); err != nil {
					w.logger.Error("can't finalize version after all checkpoints restored",
						"err", err,
						"version", prevVersion,
						"roots", syncState.Roots,
					)
					// Likely a local problem, so just bail.
					return nil, fmt.Errorf("can't finalize version after checkpoints restored: %w", err)
				}
				multipartRunning = false
				return &syncState, nil
			}
			continue
		case checkpointStatusNext:
			w.logger.Info("error trying to restore from checkpoint, trying next most recent", "root", check.Root, "err", err)
			continue
		case checkpointStatusBail:
			w.logger.Error("error trying to restore from checkpoint, unrecoverable", "root", check.Root, "err", err)
			return nil, fmt.Errorf("error restoring from checkpoints: %w", err)
		}
	}

	return nil, ErrNoUsableCheckpoints
}
