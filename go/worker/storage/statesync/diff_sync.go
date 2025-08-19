package statesync

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/workerpool"
	"github.com/oasisprotocol/oasis-core/go/config"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	dbApi "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/diffsync"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/synclegacy"
)

const (
	// maxInFlightRounds is the maximum number of rounds that should be fetched before waiting
	// for them to be applied.
	maxInFlightRounds = 100
)

type roundItem interface {
	GetRound() uint64
}

// minRoundQueue is a Round()-based min priority queue.
type minRoundQueue []roundItem

// Sorting interface.
func (q minRoundQueue) Len() int           { return len(q) }
func (q minRoundQueue) Less(i, j int) bool { return q[i].GetRound() < q[j].GetRound() }
func (q minRoundQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }

// Push appends x as the last element in the heap's array.
func (q *minRoundQueue) Push(x any) {
	*q = append(*q, x.(roundItem))
}

// Pop removes and returns the last element in the heap's array.
func (q *minRoundQueue) Pop() any {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

// fetchedDiff has all the context needed for a single GetDiff operation.
type fetchedDiff struct {
	fetched  bool
	pf       rpc.PeerFeedback
	err      error
	round    uint64
	prevRoot api.Root
	thisRoot api.Root
	writeLog api.WriteLog
}

func (d *fetchedDiff) GetRound() uint64 {
	return d.round
}

type finalizedResult struct {
	summary *blockSummary
	err     error
}

// syncDiffs is responsible for fetching, applying and finalizing storage diffs
// as the new runtimes block headers arrive from the consensus service.
//
// In addition, it is also responsible for updating availability of the registration
// service and notifying block history and checkpointer of the newly finalized rounds.
//
// Suggestion: Ideally syncDiffs is refactored into independent worker and made only
// responsible for the syncing.
func (w *Worker) syncDiffs(
	ctx context.Context,
	lastFinalizedRound uint64,
) error {
	syncingRounds := make(map[uint64]*inFlight)
	summaryCache := make(map[uint64]*blockSummary)
	pendingApply := &minRoundQueue{}
	pendingFinalize := &minRoundQueue{} // Suggestion: slice would suffice given that application must happen in order.

	diffCh := make(chan *fetchedDiff)
	finalizedCh := make(chan finalizedResult)

	fetchPool := workerpool.New("storage_fetch/" + w.commonNode.Runtime.ID().String())
	fetchPool.Resize(config.GlobalConfig.Storage.FetcherCount)
	defer fetchPool.Stop()
	fetchCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	heartbeat := heartbeat{}
	heartbeat.reset()
	defer heartbeat.Stop()

	var wg sync.WaitGroup
	defer wg.Wait()

	lastFullyAppliedRound := lastFinalizedRound
	// Don't register availability immediately, we want to know first how far behind consensus we are.
	latestBlockRound := w.undefinedRound
	for {
		// Drain the Apply and Finalize queues first, before waiting for new events in the select below.

		// Apply fetched writelogs, but only if they are for the round after the last fully applied one
		// and current number of pending roots to be finalized is smaller than max allowed.
		applyNext := pendingApply.Len() > 0 &&
			lastFullyAppliedRound+1 == (*pendingApply)[0].GetRound() &&
			pendingFinalize.Len() < dbApi.MaxPendingVersions-1 // -1 since one may be already finalizing.
		if applyNext {
			lastDiff := heap.Pop(pendingApply).(*fetchedDiff)
			err := w.apply(ctx, lastDiff)

			syncing := syncingRounds[lastDiff.round]
			if err != nil {
				syncing.retry(lastDiff.thisRoot.Type)
				continue
			}
			syncing.outstanding.remove(lastDiff.thisRoot.Type)
			if !syncing.outstanding.isEmpty() || !syncing.awaitingRetry.isEmpty() {
				continue
			}

			// We have fully synced the given round.
			w.logger.Debug("finished syncing round", "round", lastDiff.round)
			delete(syncingRounds, lastDiff.round)
			summary := summaryCache[lastDiff.round]
			delete(summaryCache, lastDiff.round-1)
			lastFullyAppliedRound = lastDiff.round

			// Suggestion: Rename to lastAppliedRoundMetric, as synced is synonim for finalized in this code.
			storageWorkerLastSyncedRound.With(w.getMetricLabels()).Set(float64(lastDiff.round))
			// Suggestion: Ideally this would be recorded once the round is finalized (synced).
			storageWorkerRoundSyncLatency.With(w.getMetricLabels()).Observe(time.Since(syncing.startedAt).Seconds())

			// Trigger finalization for this round, that will happen concurently
			// with respect to Apply operations for subsequent rounds.
			heap.Push(pendingFinalize, summary)

			continue
		}

		// Check if any new rounds were fully applied and need to be finalized.
		// Only finalize if it's the round after the one that was finalized last.
		// As a consequence at most one finalization can be happening at the time.
		if len(*pendingFinalize) > 0 && lastFinalizedRound+1 == (*pendingFinalize)[0].GetRound() {
			summary := heap.Pop(pendingFinalize).(*blockSummary)
			wg.Add(1)
			go func() { // Don't block fetching and applying remaining rounds.
				defer wg.Done()
				w.finalize(ctx, summary, finalizedCh)
			}()
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case inBlk := <-w.blockCh.Out():
			blk := inBlk.(*block.Block)
			w.logger.Debug("incoming block",
				"round", blk.Header.Round,
				"last_fully_applied", lastFullyAppliedRound,
				"last_finalized", lastFinalizedRound,
			)

			// Check if we're far enough to reasonably register as available.
			latestBlockRound = blk.Header.Round
			// Fixme: If block channel has many pending blocks (e.g. after checkpoint sync),
			// nudgeAvailability may incorrectly set the node as available too early.
			w.nudgeAvailability(lastFinalizedRound, latestBlockRound)

			if err := w.fetchMissingBlockHeaders(ctx, lastFullyAppliedRound, blk, summaryCache); err != nil {
				return fmt.Errorf("failed to fetch missing block headers: %w", err) // Suggestion: databases can fail, consider retrying.
			}

			w.triggerRoundFetches(fetchCtx, &wg, fetchPool, diffCh, syncingRounds, summaryCache, lastFullyAppliedRound+1, latestBlockRound)
		case item := <-diffCh:
			if item.err != nil {
				w.logger.Error("error calling getdiff",
					"err", item.err,
					"round", item.round,
					"old_root", item.prevRoot,
					"new_root", item.thisRoot,
					"fetched", item.fetched,
				)
				syncingRounds[item.round].retry(item.thisRoot.Type) // Suggestion: Trigger fetches immediately.
				break
			}

			heap.Push(pendingApply, item)
			// Item was successfully processed, trigger more round fetches.
			// This ensures that new rounds are processed as fast as possible
			// when we're syncing and are far behind.
			w.triggerRoundFetches(fetchCtx, &wg, fetchPool, diffCh, syncingRounds, summaryCache, lastFullyAppliedRound+1, latestBlockRound)
			heartbeat.reset()
		case <-heartbeat.C:
			if latestBlockRound != w.undefinedRound {
				w.logger.Debug("heartbeat", "in_flight_rounds", len(syncingRounds))
				w.triggerRoundFetches(fetchCtx, &wg, fetchPool, diffCh, syncingRounds, summaryCache, lastFullyAppliedRound+1, latestBlockRound)
			}
		case finalized := <-finalizedCh:
			var err error
			lastFinalizedRound, err = w.flushSyncedState(finalized.summary)
			if err != nil { // Suggestion: DB operations can always fail, consider retrying.
				return fmt.Errorf("failed to flush synced state: %w", err)
			}
			storageWorkerLastFullRound.With(w.getMetricLabels()).Set(float64(finalized.summary.Round))

			// Check if we're far enough to reasonably register as available.
			w.nudgeAvailability(lastFinalizedRound, latestBlockRound)

			// Notify the checkpointer that there is a new finalized round.
			if config.GlobalConfig.Storage.Checkpointer.Enabled {
				w.checkpointer.NotifyNewVersion(finalized.summary.Round)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (w *Worker) fetchMissingBlockHeaders(ctx context.Context, lastFullyAppliedRound uint64, blk *block.Block, summaryCache map[uint64]*blockSummary) error {
	if _, ok := summaryCache[lastFullyAppliedRound]; !ok && lastFullyAppliedRound == w.undefinedRound { // Suggestion: Helper that is only done once.
		dummy := blockSummary{
			Namespace: blk.Header.Namespace,
			Round:     lastFullyAppliedRound + 1,
			Roots: []api.Root{
				{
					Version: lastFullyAppliedRound + 1,
					Type:    api.RootTypeIO,
				},
				{
					Version: lastFullyAppliedRound + 1,
					Type:    api.RootTypeState,
				},
			},
		}
		dummy.Roots[0].Empty()
		dummy.Roots[1].Empty()
		summaryCache[lastFullyAppliedRound] = &dummy
	}
	// Determine if we need to fetch any old block summaries. In case the first
	// round is an undefined round, we need to start with the following round
	// since the undefined round may be unsigned -1 and in this case the loop
	// would not do any iterations.
	startSummaryRound := lastFullyAppliedRound
	if startSummaryRound == w.undefinedRound {
		startSummaryRound++
	}
	for i := startSummaryRound; i < blk.Header.Round; i++ {
		if _, ok := summaryCache[i]; ok {
			continue
		}
		oldBlock, err := w.commonNode.Runtime.History().GetCommittedBlock(ctx, i)
		if err != nil {
			return fmt.Errorf("getting block for round %d (current round: %d): %w", i, blk.Header.Round, err)
		}
		summaryCache[i] = summaryFromBlock(oldBlock)
	}
	if _, ok := summaryCache[blk.Header.Round]; !ok {
		summaryCache[blk.Header.Round] = summaryFromBlock(blk)
	}
	return nil
}

func (w *Worker) triggerRoundFetches(
	ctx context.Context,
	wg *sync.WaitGroup,
	fetchPool *workerpool.Pool,
	diffCh chan<- *fetchedDiff,
	syncingRounds map[uint64]*inFlight,
	summaryCache map[uint64]*blockSummary,
	start uint64,
	end uint64,
) {
	for r := start; r <= end; r++ {
		syncing, ok := syncingRounds[r]
		if ok && syncing.outstanding.hasAll() {
			continue
		}

		if !ok {
			if len(syncingRounds) >= maxInFlightRounds {
				break
			}

			syncing = &inFlight{
				startedAt:     time.Now(),
				awaitingRetry: outstandingMaskFull,
			}
			syncingRounds[r] = syncing

			if r == end {
				storageWorkerLastPendingRound.With(w.getMetricLabels()).Set(float64(r))
			}
		}
		w.logger.Debug("preparing round sync",
			"round", r,
			"outstanding_mask", syncing.outstanding,
			"awaiting_retry", syncing.awaitingRetry,
		)

		prev := summaryCache[r-1]
		this := summaryCache[r]
		prevRoots := make([]api.Root, len(prev.Roots))
		copy(prevRoots, prev.Roots)
		for i := range prevRoots {
			if prevRoots[i].Type == api.RootTypeIO {
				// IO roots aren't chained, so clear it (but leave cache intact).
				prevRoots[i] = api.Root{
					Namespace: this.Namespace,
					Version:   this.Round,
					Type:      api.RootTypeIO,
				}
				prevRoots[i].Hash.Empty()
				break
			}
		}

		for i := range prevRoots {
			rootType := prevRoots[i].Type
			if !syncing.outstanding.contains(rootType) && syncing.awaitingRetry.contains(rootType) {
				syncing.scheduleDiff(rootType)
				wg.Add(1)
				fetchPool.Submit(func() {
					defer wg.Done()
					w.fetchDiff(ctx, diffCh, this.Round, prevRoots[i], this.Roots[i])
				})
			}
		}
	}
}

func (w *Worker) fetchDiff(ctx context.Context, fetchCh chan<- *fetchedDiff, round uint64, prevRoot, thisRoot api.Root) {
	result := &fetchedDiff{
		fetched:  false,
		pf:       rpc.NewNopPeerFeedback(),
		round:    round,
		prevRoot: prevRoot,
		thisRoot: thisRoot,
	}
	defer func() {
		select {
		case fetchCh <- result:
		case <-ctx.Done():
		}
	}()

	// Check if the new root doesn't already exist.
	if w.localStorage.NodeDB().HasRoot(thisRoot) {
		return
	}

	result.fetched = true

	// Even if HasRoot returns false the root can still exist if it is equal
	// to the previous root and the root was emitted by the consensus committee
	// directly (e.g., during an epoch transition).
	if thisRoot.Hash.Equal(&prevRoot.Hash) {
		result.writeLog = api.WriteLog{}
		return
	}

	// New root does not yet exist in storage and we need to fetch it from a peer.
	w.logger.Debug("calling GetDiff",
		"old_root", prevRoot,
		"new_root", thisRoot,
	)

	wl, pf, err := w.getDiff(ctx, prevRoot, thisRoot)
	if err != nil {
		result.err = err
		return
	}
	result.pf = pf
	result.writeLog = wl
}

// getDiff fetches writelog using diff sync p2p protocol client.
//
// The request relies on the default timeout of the underlying p2p protocol clients.
//
// In case of no peers or error, it fallbacks to the legacy storage sync protocol.
func (w *Worker) getDiff(ctx context.Context, prevRoot, thisRoot api.Root) (api.WriteLog, rpc.PeerFeedback, error) {
	rsp1, pf, err := w.diffSync.GetDiff(ctx, &diffsync.GetDiffRequest{StartRoot: prevRoot, EndRoot: thisRoot})
	if err == nil { // if NO error
		return rsp1.WriteLog, pf, nil
	}

	rsp2, pf, err := w.legacyStorageSync.GetDiff(ctx, &synclegacy.GetDiffRequest{StartRoot: prevRoot, EndRoot: thisRoot})
	if err != nil {
		return nil, nil, err
	}
	return rsp2.WriteLog, pf, nil
}

func (w *Worker) apply(ctx context.Context, diff *fetchedDiff) error {
	if !diff.fetched {
		return nil
	}

	err := w.localStorage.Apply(ctx, &api.ApplyRequest{
		Namespace: diff.thisRoot.Namespace,
		RootType:  diff.thisRoot.Type,
		SrcRound:  diff.prevRoot.Version,
		SrcRoot:   diff.prevRoot.Hash,
		DstRound:  diff.thisRoot.Version,
		DstRoot:   diff.thisRoot.Hash,
		WriteLog:  diff.writeLog,
	})
	switch {
	case err == nil:
		diff.pf.RecordSuccess()
	case errors.Is(err, api.ErrExpectedRootMismatch):
		diff.pf.RecordBadPeer()
	default:
		w.logger.Error("can't apply write log",
			"err", err,
			"old_root", diff.prevRoot,
			"new_root", diff.thisRoot,
		)
		diff.pf.RecordSuccess()
	}

	return err
}

func (w *Worker) finalize(ctx context.Context, summary *blockSummary, finalizedCh chan<- finalizedResult) {
	err := w.localStorage.NodeDB().Finalize(summary.Roots)
	switch err {
	case nil:
		w.logger.Debug("storage round finalized",
			"round", summary.Round,
		)
	case api.ErrAlreadyFinalized:
		// This can happen if we are restoring after a roothash migration or if
		// we crashed before updating the sync state.
		w.logger.Warn("storage round already finalized",
			"round", summary.Round,
		)
		err = nil
	default:
		w.logger.Error("failed to finalize", "err", err, "summary", summary)
	}

	result := finalizedResult{
		summary: summary,
		err:     err,
	}

	select {
	case finalizedCh <- result:
	case <-ctx.Done():
	}
}
