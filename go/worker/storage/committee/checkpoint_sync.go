package committee

import (
	"bytes"
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	storageSync "github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/sync"
)

const (
	// cpListsTimeout is the timeout for fetching checkpoints from all nodes.
	cpListsTimeout = 30 * time.Second
	// cpRestoreTimeout is the timeout for restoring a checkpoint chunk from a node.
	cpRestoreTimeout = 60 * time.Second

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
	// Disabled specifies whether checkpoint sync should be disabled. In this case the node will
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
	checkpoint *storageSync.Checkpoint
}

type chunkHeap struct {
	array  []*chunk
	length int
}

func (h chunkHeap) Len() int           { return h.length }
func (h chunkHeap) Less(i, j int) bool { return h.array[i].Index < h.array[j].Index }
func (h chunkHeap) Swap(i, j int)      { h.array[i], h.array[j] = h.array[j], h.array[i] }

func (h *chunkHeap) Push(x interface{}) {
	h.array[h.length] = x.(*chunk)
	h.length++
}

func (h *chunkHeap) Pop() interface{} {
	h.length--
	ret := h.array[h.length]
	h.array[h.length] = nil
	return ret
}

func (n *Node) checkpointChunkFetcher(
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

		chunkCtx, cancel := context.WithTimeout(ctx, cpRestoreTimeout)
		defer cancel()

		// Fetch chunk from peers.
		rsp, pf, err := n.storageSync.GetCheckpointChunk(chunkCtx, &storageSync.GetCheckpointChunkRequest{
			Version: chunk.Version,
			Root:    chunk.Root,
			Index:   chunk.Index,
			Digest:  chunk.Digest,
		}, chunk.checkpoint)
		if err != nil {
			n.logger.Error("failed to fetch chunk from peers",
				"err", err,
				"chunk", chunk.Index,
			)
			chunkReturnCh <- chunk
			continue
		}

		// Restore fetched chunk.
		done, err := n.localStorage.Checkpointer().RestoreChunk(chunkCtx, chunk.Index, bytes.NewBuffer(rsp.Chunk))
		cancel()

		switch {
		case done:
			pf.RecordSuccess()
			// Signal to the toplevel handler that we're done.
			chunkReturnCh <- nil
			return
		case err != nil:
			n.logger.Error("chunk restoration failed",
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

func (n *Node) handleCheckpoint(check *storageSync.Checkpoint, maxParallelRequests uint) (cpStatus int, rerr error) {
	if err := n.localStorage.Checkpointer().StartRestore(n.ctx, check.Metadata); err != nil {
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
		if err := n.localStorage.Checkpointer().AbortRestore(ctx); err != nil {
			cpStatus = checkpointStatusBail
			n.logger.Error("error while aborting checkpoint restore on handler exit, aborting sync",
				"err", err,
			)
		}
	}()

	chunkDispatchCh := make(chan *chunk)
	defer close(chunkDispatchCh)

	chunkReturnCh := make(chan *chunk, maxParallelRequests)
	errorCh := make(chan int, maxParallelRequests)

	ctx, cancel := context.WithCancel(n.ctx)

	// Spawn the worker group to fetch and restore checkpoint chunks.
	var workerGroup sync.WaitGroup
	doneCh := make(chan interface{})
	for i := uint(0); i < maxParallelRequests; i++ {
		workerGroup.Add(1)
		go func() {
			defer workerGroup.Done()
			n.checkpointChunkFetcher(ctx, chunkDispatchCh, chunkReturnCh, errorCh)
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
	n.logger.Debug("checkpoint chunks prepared for dispatch",
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
		case <-n.ctx.Done():
			return checkpointStatusBail, n.ctx.Err()

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

func (n *Node) getCheckpointList() ([]*storageSync.Checkpoint, error) {
	ctx, cancel := context.WithTimeout(n.ctx, cpListsTimeout)
	defer cancel()

	list, err := n.storageSync.GetCheckpoints(ctx, &storageSync.GetCheckpointsRequest{
		Version: 1,
	})
	if err != nil {
		n.logger.Error("failed to retrieve any checkpoints",
			"err", err,
		)
		return nil, err
	}

	// Sort checkpoints by version, descending.
	sort.Slice(list, func(i, j int) bool {
		// Descending!
		if list[j].Root.Version == list[i].Root.Version {
			return bytes.Compare(list[j].Root.Hash[:], list[i].Root.Hash[:]) < 0
		}
		return list[j].Root.Version < list[i].Root.Version
	})
	return list, nil
}

func (n *Node) checkCheckpointUsable(cp *storageSync.Checkpoint, remainingMask outstandingMask) bool {
	namespace := n.commonNode.Runtime.ID()
	if !namespace.Equal(&cp.Root.Namespace) {
		// Not for the right runtime.
		return false
	}
	blk, err := n.commonNode.Runtime.History().GetCommittedBlock(n.ctx, cp.Root.Version)
	if err != nil {
		n.logger.Error("can't get block information for checkpoint, skipping", "err", err, "root", cp.Root)
		return false
	}
	_, lastIORoot, lastStateRoot := n.GetLastSynced()
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
	n.logger.Info("checkpoint for unknown root skipped", "root", cp.Root)
	return false
}

func (n *Node) syncCheckpoints(genesisRound uint64, wantOnlyGenesis bool) (*blockSummary, error) {
	// Store roots and round info for checkpoints that finished syncing.
	// Round and namespace info will get overwritten as rounds are skipped
	// for errors, driven by remainingRoots.
	var syncState blockSummary

	// Fetch checkpoints from peers.
	cps, err := n.getCheckpointList()
	if err != nil {
		return nil, fmt.Errorf("can't get checkpoint list from peers: %w", err)
	}

	// If we only want the genesis checkpoint, filter it out.
	if wantOnlyGenesis && len(cps) > 0 {
		var filteredCps []*storageSync.Checkpoint
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
		if err := n.localStorage.NodeDB().AbortMultipartInsert(); err != nil {
			n.logger.Error("error aborting multipart restore on exit from syncer",
				"err", err,
			)
		}
	}()

	for _, check := range cps {
		if check.Root.Version < genesisRound || !n.checkCheckpointUsable(check, remainingRoots) {
			continue
		}

		if check.Root.Version != prevVersion {
			// Starting a new round, so we need to clean up all state from
			// previous retores. Aborting multipart works with no multipart in
			// progress too.
			multipartRunning = false
			if err := n.localStorage.NodeDB().AbortMultipartInsert(); err != nil {
				return nil, fmt.Errorf("error aborting previous multipart restore: %w", err)
			}
			if err := n.localStorage.NodeDB().StartMultipartInsert(check.Root.Version); err != nil {
				return nil, fmt.Errorf("error starting multipart insert for round %d: %w", check.Root.Version, err)
			}
			multipartRunning = true
			remainingRoots = outstandingMaskFull
			prevVersion = check.Root.Version
			syncState.Roots = nil
		}

		status, err := n.handleCheckpoint(check, n.checkpointSyncCfg.ChunkFetcherCount)
		switch status {
		case checkpointStatusDone:
			n.logger.Info("successfully restored from checkpoint", "root", check.Root, "mask", mask)

			syncState.Namespace = check.Root.Namespace
			syncState.Round = check.Root.Version
			syncState.Roots = append(syncState.Roots, check.Root)
			remainingRoots.remove(check.Root.Type)
			if remainingRoots.isEmpty() {
				if err = n.localStorage.NodeDB().Finalize(n.ctx, syncState.Roots); err != nil {
					n.logger.Error("can't finalize version after all checkpoints restored",
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
			n.logger.Info("error trying to restore from checkpoint, trying next most recent", "root", check.Root, "err", err)
			continue
		case checkpointStatusBail:
			n.logger.Error("error trying to restore from checkpoint, unrecoverable", "root", check.Root, "err", err)
			return nil, fmt.Errorf("error restoring from checkpoints: %w", err)
		}
	}

	return nil, ErrNoUsableCheckpoints
}
