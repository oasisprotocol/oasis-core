package diffsync

import (
	"container/heap"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	storageApi "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/diffsync"
	"github.com/oasisprotocol/oasis-core/go/worker/storage/p2p/synclegacy"
)

type P2PFetcher struct {
	logger            *logging.Logger
	history           history.History
	diffSync          diffsync.Client
	legacyStorageSync synclegacy.Client
	undefinedRound    uint64
	lastFullyApplied  uint64
	nextCh            chan Diff
	acceptCh          chan struct{}
	rejectCh          chan struct{}
	rejectTaskCh      chan fetchTask
	diffCh            chan diffRes
	fetcherCount      uint
}

func NewP2PFetcher(
	history history.History,
	diffSync diffsync.Client,
	legacyStorageSync synclegacy.Client,
	lastFullyApplied,
	undefinedRound uint64,
	fetcherCount uint,
) *P2PFetcher {
	return &P2PFetcher{
		logger:            logging.GetLogger("worker/storage/committee/fetcher").With("runtime_id", history.RuntimeID()),
		history:           history,
		diffSync:          diffSync,
		legacyStorageSync: legacyStorageSync,
		undefinedRound:    undefinedRound,
		lastFullyApplied:  lastFullyApplied,
		nextCh:            make(chan Diff),
		diffCh:            make(chan diffRes),
		rejectCh:          make(chan struct{}, 1),
		acceptCh:          make(chan struct{}, 1),
		rejectTaskCh:      make(chan fetchTask), // TODO consider adding more.
		fetcherCount:      fetcherCount,
	}
}

// Next returns whean a next storage diff is ready to be applied.
//
// Invariants:
//   - A call to Next is blocking.
//   - It is not safe to call next before either Acceept and or Reject.
//   - The order of storage and IO diffs for a single round is not guaranteed.
func (f *P2PFetcher) Next(ctx context.Context) (Diff, error) {
	for {
		select {
		case <-ctx.Done():
			return Diff{}, ctx.Err()
		case diff, ok := <-f.nextCh:
			if !ok {
				return Diff{}, fmt.Errorf("fetcher closed")
			}
			return diff, nil
		}
	}
}

// Accept accepts a storage diff obtained via call to Next.
func (f *P2PFetcher) Accept() {
	select {
	case f.acceptCh <- struct{}{}:
	default:
	}
}

// Reject rejects a storage diff obtained via call to Next.
func (f *P2PFetcher) Reject() {
	select {
	case f.rejectCh <- struct{}{}:
	default:
	}
}

func (f *P2PFetcher) Serve(ctx context.Context) error {
	var (
		lastDiff      diffRes
		acceptedCount int
		pendingAck    bool
	)
	pendingApply := &minRoundQueue{}

	lastFullyApplied := f.lastFullyApplied

	var wg sync.WaitGroup
	defer wg.Wait()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	producer, taskCh := newTaskProducer(f.history, f.logger, lastFullyApplied, f.undefinedRound, f.fetcherCount)
	wg.Go(func() {
		if err := producer.serve(ctx); err != nil {
			f.logger.Error("producer failed", "err", err)
		}
	})

	for i := uint(0); i < f.fetcherCount; i++ {
		wg.Go(func() {
			for task := range taskCh {
				res, _ := f.fetchWithRetry(ctx, task) // TODO handle the error or omit it.
				select {
				case f.diffCh <- res:
				case <-ctx.Done():
				}
			}
		})
	}

	wg.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case task := <-f.rejectTaskCh:
				res, _ := f.fetchWithRetry(ctx, task) // TODO handle the error or omit it.
				select {
				case f.diffCh <- res:
				case <-ctx.Done():
				}
			}
		}
	})

	trySendingNextForApply := func() {
		if pendingAck {
			return
		}
		hasNext := pendingApply.Len() > 0 && lastFullyApplied+1 == (*pendingApply)[0].round
		if !hasNext {
			return
		}
		pendingAck = true
		lastDiff = heap.Pop(pendingApply).(diffRes)
		wg.Go(func() {
			select {
			case <-ctx.Done():
				return
			case f.nextCh <- Diff{
				round:    lastDiff.round,
				prevRoot: lastDiff.prevRoot,
				thisRoot: lastDiff.thisRoot,
				writeLog: lastDiff.writeLog}:
			}
		})
	}

	for {
		select { // For optimal performance no case should be blocking.
		case <-ctx.Done():
			return ctx.Err()
		case diff := <-f.diffCh:
			heap.Push(pendingApply, diff)
			trySendingNextForApply()
		case <-f.rejectCh:
			lastDiff.pf.RecordBadPeer()
			pendingAck = false
			select {
			case <-ctx.Done():
				return ctx.Err()
			case f.rejectTaskCh <- lastDiff.fetchTask:
			}
		case <-f.acceptCh:
			lastDiff.pf.RecordSuccess()
			acceptedCount++
			if acceptedCount == 2 {
				lastFullyApplied++
				acceptedCount = 0
			}
			pendingAck = false
			trySendingNextForApply()
		}
	}
}

// TODO add backoff.
func (f *P2PFetcher) fetchWithRetry(ctx context.Context, task fetchTask) (diffRes, error) {
	result := diffRes{
		fetchTask: task,
		pf:        rpc.NewNopPeerFeedback(),
	}

	if task.thisRoot.Hash.Equal(&task.prevRoot.Hash) {
		result.writeLog = storageApi.WriteLog{}
		return result, nil
	}

	for {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		wl, pf, err := f.getDiff(ctx, task.prevRoot, task.thisRoot)
		if err != nil {
			f.logger.Error("failed to fetch storage diff", "err", err)
			continue
		}
		result.pf = pf
		result.writeLog = wl
		return result, err
	}
}

// getDiff fetches writelog using diff sync p2p protocol client.
//
// In case of no peers or error, it fallbacks to the legacy storage sync protocol.
func (f *P2PFetcher) getDiff(ctx context.Context, prevRoot, thisRoot storageApi.Root) (storageApi.WriteLog, rpc.PeerFeedback, error) {
	f.logger.Debug("calling GetDiff",
		"old_root", prevRoot,
		"new_root", thisRoot,
	)

	// diffResponseTimeout is the maximum time for fetching storage diff from the peer.
	const diffResponseTimeout = 15 * time.Second

	ctx, cancel := context.WithTimeout(ctx, diffResponseTimeout)
	defer cancel()
	rsp1, pf, err := f.diffSync.GetDiff(ctx, &diffsync.GetDiffRequest{StartRoot: prevRoot, EndRoot: thisRoot})
	if err == nil { // if NO error
		return rsp1.WriteLog, pf, nil
	}

	ctx, cancel = context.WithTimeout(ctx, diffResponseTimeout)
	defer cancel()
	rsp2, pf, err := f.legacyStorageSync.GetDiff(ctx, &synclegacy.GetDiffRequest{StartRoot: prevRoot, EndRoot: thisRoot})
	if err != nil {
		return nil, nil, err
	}
	return rsp2.WriteLog, pf, nil
}

type fetchTask struct {
	round    uint64
	prevRoot storageApi.Root
	thisRoot storageApi.Root
}

type taskProducer struct {
	history        history.History
	logger         *logging.Logger
	undefinedRound uint64
	lastEnqueued   uint64
	prevStateRoot  storageApi.Root
	tasks          chan fetchTask
}

func newTaskProducer(
	history history.History,
	logger *logging.Logger,
	lastFullyApplied uint64,
	undefinedRound uint64,
	queueSize uint,
) (*taskProducer, <-chan fetchTask) {
	producer := &taskProducer{
		history:        history,
		logger:         logger,
		undefinedRound: undefinedRound,
		lastEnqueued:   lastFullyApplied,
		tasks:          make(chan fetchTask, queueSize),
	}
	return producer, producer.tasks
}

func (p *taskProducer) serve(ctx context.Context) error {
	blkCh, sub, err := p.history.WatchCommittedBlocks()
	if err != nil {
		return fmt.Errorf("subscribing to commited blocks: %w", err)
	}
	if err := p.initState(ctx); err != nil {
		sub.Close()
		return err
	}

	defer close(p.tasks)
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case next, ok := <-blkCh:
			if !ok {
				return nil
			}
			p.logger.Debug("producer received new block", "blk", next.Block)
			if err := p.fillUntil(ctx, next.Block); err != nil {
				p.logger.Warn("failed to fill fetch task gap: %w", err)
			}
		}
	}
}

func (p *taskProducer) initState(ctx context.Context) error {
	if p.lastEnqueued == p.undefinedRound {
		p.prevStateRoot = storageApi.Root{
			Namespace: p.history.RuntimeID(),
			Version:   p.lastEnqueued + 1,
			Type:      storageApi.RootTypeState,
		}
		p.prevStateRoot.Empty()
		return nil
	}

	blk, err := p.history.GetCommittedBlock(ctx, p.lastEnqueued)
	if err != nil {
		return fmt.Errorf("get history block (round: %d): %w", p.lastEnqueued, err)
	}
	p.prevStateRoot = blk.Header.StorageRootState()
	return nil
}

func (p *taskProducer) enqueue(ctx context.Context, blk *block.Block) {
	emit := func(task fetchTask) {
		select {
		case <-ctx.Done():
			return
		case p.tasks <- task:
			p.logger.Debug("enqueued new fetch task", "task", task)
		}
	}

	thisIORoot := blk.Header.StorageRootIO()
	prevIORoot := thisIORoot
	prevIORoot.Hash.Empty()
	emit(fetchTask{blk.Header.Round, prevIORoot, thisIORoot})

	thisStateRoot := blk.Header.StorageRootState()
	emit(fetchTask{blk.Header.Round, p.prevStateRoot, thisStateRoot})
	p.prevStateRoot = thisStateRoot

	p.lastEnqueued = blk.Header.Round
}

func (p *taskProducer) fillUntil(ctx context.Context, blk *block.Block) error {
	for r := p.lastEnqueued + 1; r < blk.Header.Round; r++ {
		blk, err := p.history.GetCommittedBlock(ctx, r)
		if err != nil {
			return fmt.Errorf("failed to get light block (round: %d): %w", r, err)
		}
		p.enqueue(ctx, blk)
	}
	p.enqueue(ctx, blk)
	return nil
}

// minRoundQueue is a round-based min priority queue.
type minRoundQueue []diffRes

// Sorting interface.
func (q minRoundQueue) Len() int           { return len(q) }
func (q minRoundQueue) Less(i, j int) bool { return q[i].round < q[j].round }
func (q minRoundQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }

// Push appends x as the last element in the heap's array.
func (q *minRoundQueue) Push(x any) {
	*q = append(*q, x.(diffRes))
}

// Pop removes and returns the last element in the heap's array.
func (q *minRoundQueue) Pop() any {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

// diffRes has all the context needed for a single GetDiff operation.
type diffRes struct {
	fetchTask
	pf       rpc.PeerFeedback
	writeLog storageApi.WriteLog
}
