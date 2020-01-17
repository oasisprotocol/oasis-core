package committee

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/eapache/channels"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/persistent"
	"github.com/oasislabs/oasis-core/go/common/workerpool"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	roothashApi "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	storageApi "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/client"
	urkelNode "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
	"github.com/oasislabs/oasis-core/go/worker/registration"
)

var (
	_ committee.NodeHooks = (*Node)(nil)

	// ErrNonLocalBackend is the error returned when the storage backend doesn't implement the LocalBackend interface.
	ErrNonLocalBackend = errors.New("storage: storage backend doesn't support local storage")
)

const (
	// RoundLatest is a magic value for the latest round.
	RoundLatest = math.MaxUint64

	defaultUndefinedRound = ^uint64(0)
)

// outstandingMask records which storage roots still need to be synced or need to be retried.
type outstandingMask uint

const (
	maskNone  = outstandingMask(0x0)
	maskIO    = outstandingMask(0x1)
	maskState = outstandingMask(0x2)
	maskAll   = maskIO | maskState
)

func (o outstandingMask) String() string {
	var represented []string
	if o&maskIO != 0 {
		represented = append(represented, "io")
	}
	if o&maskState != 0 {
		represented = append(represented, "state")
	}
	return fmt.Sprintf("outstanding_mask{%s}", strings.Join(represented, ", "))
}

type roundItem interface {
	GetRound() uint64
}

// outOfOrderRoundQueue is a Round()-based min priority queue.
type outOfOrderRoundQueue []roundItem

// Sorting interface.
func (q outOfOrderRoundQueue) Len() int           { return len(q) }
func (q outOfOrderRoundQueue) Less(i, j int) bool { return q[i].GetRound() < q[j].GetRound() }
func (q outOfOrderRoundQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }

// Push appends x as the last element in the heap's array.
func (q *outOfOrderRoundQueue) Push(x interface{}) {
	*q = append(*q, x.(roundItem))
}

// Pop removes and returns the last element in the heap's array.
func (q *outOfOrderRoundQueue) Pop() interface{} {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

// fetchedDiff has all the context needed for a single GetDiff operation.
type fetchedDiff struct {
	fetchMask outstandingMask
	fetched   bool
	err       error
	round     uint64
	prevRoot  urkelNode.Root
	thisRoot  urkelNode.Root
	writeLog  storageApi.WriteLog
}

func (d *fetchedDiff) GetRound() uint64 {
	return d.round
}

// blockSummary is a short summary of a single block.Block.
type blockSummary struct {
	Namespace common.Namespace `json:"namespace"`
	Round     uint64           `json:"round"`
	IORoot    urkelNode.Root   `json:"io_root"`
	StateRoot urkelNode.Root   `json:"state_root"`
}

func (s *blockSummary) GetRound() uint64 {
	return s.Round
}

func summaryFromBlock(blk *block.Block) *blockSummary {
	return &blockSummary{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
		IORoot: urkelNode.Root{
			Namespace: blk.Header.Namespace,
			Round:     blk.Header.Round,
			Hash:      blk.Header.IORoot,
		},
		StateRoot: urkelNode.Root{
			Namespace: blk.Header.Namespace,
			Round:     blk.Header.Round,
			Hash:      blk.Header.StateRoot,
		},
	}
}

// watcherState is the (persistent) watcher state.
type watcherState struct {
	LastBlock blockSummary `json:"last_block"`
}

// Node watches blocks for storage changes.
type Node struct {
	commonNode *committee.Node

	roleProvider registration.RoleProvider

	logger *logging.Logger

	localStorage   storageApi.LocalBackend
	storageClient  storageApi.ClientBackend
	grpcPolicy     *grpc.DynamicRuntimePolicyChecker
	undefinedRound uint64

	fetchPool *workerpool.Pool

	stateStore *persistent.ServiceStore

	syncedLock  sync.RWMutex
	syncedState watcherState

	blockCh    *channels.InfiniteChannel
	diffCh     chan *fetchedDiff
	finalizeCh chan *blockSummary

	ctx       context.Context
	ctxCancel context.CancelFunc

	quitCh chan struct{}
	initCh chan struct{}
}

func NewNode(
	commonNode *committee.Node,
	grpcPolicy *grpc.DynamicRuntimePolicyChecker,
	fetchPool *workerpool.Pool,
	store *persistent.ServiceStore,
	roleProvider registration.RoleProvider,
) (*Node, error) {
	localStorage, ok := commonNode.Storage.(storageApi.LocalBackend)
	if !ok {
		return nil, ErrNonLocalBackend
	}

	node := &Node{
		commonNode: commonNode,

		roleProvider: roleProvider,

		logger: logging.GetLogger("worker/storage/committee").With("runtime_id", commonNode.Runtime.ID()),

		localStorage: localStorage,
		grpcPolicy:   grpcPolicy,

		fetchPool: fetchPool,

		stateStore: store,

		blockCh:    channels.NewInfiniteChannel(),
		diffCh:     make(chan *fetchedDiff),
		finalizeCh: make(chan *blockSummary),

		quitCh: make(chan struct{}),
		initCh: make(chan struct{}),
	}

	node.syncedState.LastBlock.Round = defaultUndefinedRound
	rtID := commonNode.Runtime.ID()
	err := store.GetCBOR(rtID[:], &node.syncedState)
	if err != nil && err != persistent.ErrNotFound {
		return nil, err
	}

	node.ctx, node.ctxCancel = context.WithCancel(context.Background())

	var ns common.Namespace
	runtimeID := commonNode.Runtime.ID()
	copy(ns[:], runtimeID[:])

	// Create a new storage client that will be used for remote sync.
	scl, err := client.New(node.ctx, ns, node.commonNode.Identity, node.commonNode.Scheduler, node.commonNode.Registry)
	if err != nil {
		return nil, err
	}
	node.storageClient = scl.(storageApi.ClientBackend)

	// Register prune handler.
	commonNode.Runtime.History().Pruner().RegisterHandler(&pruneHandler{
		logger:    node.logger,
		node:      node,
		namespace: ns,
	})

	return node, nil
}

// Service interface.

// Name returns the service name.
func (n *Node) Name() string {
	return "committee node"
}

// Start causes the worker to start responding to tendermint new block events.
func (n *Node) Start() error {
	go n.worker()
	return nil
}

// Stop causes the worker to stop watching and shut down.
func (n *Node) Stop() {
	n.ctxCancel()
}

// Quit returns a channel that will be closed when the worker stops.
func (n *Node) Quit() <-chan struct{} {
	return n.quitCh
}

// Cleanup cleans up any leftover state after the worker is stopped.
func (n *Node) Cleanup() {
	// Nothing to do here?
}

// Initialized returns a channel that will be closed once the worker finished starting up.
func (n *Node) Initialized() <-chan struct{} {
	return n.initCh
}

// NodeHooks implementation.

func (n *Node) HandlePeerMessage(context.Context, *p2p.Message) (bool, error) {
	// Nothing to do here.
	return false, nil
}

// Guarded by CrossNode.
func (n *Node) HandleEpochTransitionLocked(snapshot *committee.EpochSnapshot) {
	// Create new storage gRPC access policy for the current runtime.
	policy := accessctl.NewPolicy()
	for _, xc := range snapshot.GetExecutorCommittees() {
		if xc != nil {
			executorCommitteePolicy.AddRulesForCommittee(&policy, xc)
		}
	}
	if tsc := snapshot.GetTransactionSchedulerCommittee(); tsc != nil {
		txnSchedulerCommitteePolicy.AddRulesForCommittee(&policy, tsc)
	}
	if mc := snapshot.GetMergeCommittee(); mc != nil {
		mergeCommitteePolicy.AddRulesForCommittee(&policy, mc)
	}
	// TODO: Query registry only for storage nodes after
	// https://github.com/oasislabs/oasis-core/issues/1923 is implemented.
	nodes, err := n.commonNode.Registry.GetNodes(context.Background(), snapshot.GetGroupVersion())
	if nodes != nil {
		storageNodesPolicy.AddRulesForNodeRoles(&policy, nodes, node.RoleStorageWorker)
	} else {
		n.logger.Error("couldn't get nodes from registry", "err", err)
	}
	// Update storage gRPC access policy for the current runtime.
	n.grpcPolicy.SetAccessPolicy(policy, n.commonNode.Runtime.ID())
	n.logger.Debug("set new storage gRPC access policy", "policy", policy)
}

// Guarded by CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(*block.Block) {
	// Nothing to do here.
}

// Guarded by CrossNode.
func (n *Node) HandleNewBlockLocked(blk *block.Block) {
	select {
	case n.blockCh.In() <- blk:
	case <-n.ctx.Done():
	}
}

// Guarded by CrossNode.
func (n *Node) HandleNewEventLocked(*roothashApi.Event) {
	// Nothing to do here.
}

// Watcher implementation.

// GetLastSynced returns the height, IORoot hash and StateRoot hash of the last block that was fully synced to.
func (n *Node) GetLastSynced() (uint64, urkelNode.Root, urkelNode.Root) {
	n.syncedLock.RLock()
	defer n.syncedLock.RUnlock()

	return n.syncedState.LastBlock.Round, n.syncedState.LastBlock.IORoot, n.syncedState.LastBlock.StateRoot
}

// ForceFinalize forces a storage finalization for the given round.
func (n *Node) ForceFinalize(ctx context.Context, round uint64) error {
	n.logger.Debug("forcing round finalization",
		"round", round,
	)

	var block *block.Block
	var err error

	if round == RoundLatest {
		block, err = n.commonNode.Roothash.GetLatestBlock(ctx, n.commonNode.Runtime.ID(), consensus.HeightLatest)
	} else {
		block, err = n.commonNode.Runtime.History().GetBlock(ctx, round)
	}

	if err != nil {
		return err
	}
	return n.localStorage.Finalize(ctx, block.Header.Namespace, round, []hash.Hash{
		block.Header.IORoot,
		block.Header.StateRoot,
	})
}

func (n *Node) fetchDiff(round uint64, prevRoot *urkelNode.Root, thisRoot *urkelNode.Root, fetchMask outstandingMask) {
	result := &fetchedDiff{
		fetchMask: fetchMask,
		fetched:   false,
		round:     round,
		prevRoot:  *prevRoot,
		thisRoot:  *thisRoot,
	}
	defer func() {
		n.diffCh <- result
	}()
	// Check if the new root doesn't already exist.
	if !n.localStorage.HasRoot(*thisRoot) {
		result.fetched = true
		if thisRoot.Hash.Equal(&prevRoot.Hash) {
			// Even if HasRoot returns false the root can still exist if it is equal
			// to the previous root and the root was emitted by the consensus committee
			// directly (e.g., during an epoch transition). In this case we need to
			// still apply the (empty) write log.
			result.writeLog = storageApi.WriteLog{}
		} else {
			// New root does not yet exist in storage and we need to fetch it from a
			// remote node.
			n.logger.Debug("calling GetDiff",
				"old_root", prevRoot,
				"new_root", thisRoot,
				"fetch_mask", fetchMask,
			)

			it, err := n.storageClient.GetDiff(n.ctx, &storageApi.GetDiffRequest{StartRoot: *prevRoot, EndRoot: *thisRoot})
			if err != nil {
				result.err = err
				return
			}
			for {
				more, err := it.Next()
				if err != nil {
					result.err = err
					return
				}
				if !more {
					break
				}

				chunk, err := it.Value()
				if err != nil {
					result.err = err
					return
				}
				result.writeLog = append(result.writeLog, chunk)
			}
		}
	}
}

func (n *Node) finalize(summary *blockSummary) {
	err := n.localStorage.Finalize(n.ctx, summary.Namespace, summary.Round, []hash.Hash{
		summary.IORoot.Hash,
		summary.StateRoot.Hash,
	})
	switch err {
	case nil:
		n.logger.Debug("storage round finalized",
			"round", summary.Round,
		)
	case storageApi.ErrAlreadyFinalized:
		// This can happen if we are restoring after a roothash migration or if
		// we crashed before updating the sync state.
		n.logger.Warn("storage round already finalized",
			"round", summary.Round,
		)
	default:
		n.logger.Error("failed to finalize storage round",
			"err", err,
			"round", summary.Round,
		)
	}

	n.finalizeCh <- summary
}

type inFlight struct {
	outstanding   outstandingMask
	awaitingRetry outstandingMask
}

func (n *Node) worker() { // nolint: gocyclo
	defer close(n.quitCh)
	defer close(n.diffCh)

	// Wait for the common node to be initialized.
	select {
	case <-n.commonNode.Initialized():
	case <-n.ctx.Done():
		close(n.initCh)
		return
	}

	n.logger.Info("starting committee node")

	genesisBlock, err := n.commonNode.Roothash.GetGenesisBlock(n.ctx, n.commonNode.Runtime.ID(), consensus.HeightLatest)
	if err != nil {
		n.logger.Error("can't retrieve genesis block", "err", err)
		return
	}
	n.undefinedRound = genesisBlock.Header.Round - 1

	var fetcherGroup sync.WaitGroup

	n.syncedLock.RLock()
	cachedLastRound := n.syncedState.LastBlock.Round
	n.syncedLock.RUnlock()
	if cachedLastRound == defaultUndefinedRound || cachedLastRound < genesisBlock.Header.Round {
		cachedLastRound = n.undefinedRound
	}

	n.logger.Info("worker initialized",
		"genesis_round", genesisBlock.Header.Round,
		"last_synced", cachedLastRound,
	)

	outOfOrderDiffs := &outOfOrderRoundQueue{}
	outOfOrderApplieds := &outOfOrderRoundQueue{}
	syncingRounds := make(map[uint64]*inFlight)
	hashCache := make(map[uint64]*blockSummary)
	lastFullyAppliedRound := cachedLastRound

	heap.Init(outOfOrderDiffs)

	close(n.initCh)

	// We are now ready to service requests.
	n.roleProvider.SetAvailable(func(nd *node.Node) error {
		nd.AddOrUpdateRuntime(n.commonNode.Runtime.ID())
		return nil
	})

	// Main processing loop. When a new block comes in, its state and io roots are inspected and their
	// writelogs fetched from remote storage nodes in case we don't have them locally yet. Fetches are
	// asynchronous and, once complete, trigger local Apply operations. These are serialized
	// per round (all applies for a given round have to be complete before applying anyting for following
	// rounds) using the outOfOrderDiffs priority queue and outOfOrderApplieds. Once a round has all its write
	// logs applied, a Finalize for it is triggered, again serialized by round but otherwise asynchronous
	// (outOfOrderApplieds and cachedLastRound).
mainLoop:
	for {
		// Drain the Apply and Finalize queues first, before waiting for new events in the select
		// below. Applies are drained first, followed by finalizations (which are asynchronous
		// but serialized, i.e. only one Finalize can be in progress at a time).

		// Apply any writelogs that came in through fetchDiff, but only if they are for the round
		// after the last fully applied one (lastFullyAppliedRound).
		if len(*outOfOrderDiffs) > 0 && lastFullyAppliedRound+1 == (*outOfOrderDiffs)[0].GetRound() {
			lastDiff := heap.Pop(outOfOrderDiffs).(*fetchedDiff)
			// Apply the write log if one exists.
			if lastDiff.fetched {
				_, err = n.localStorage.Apply(n.ctx, &storageApi.ApplyRequest{
					Namespace: lastDiff.thisRoot.Namespace,
					SrcRound:  lastDiff.prevRoot.Round,
					SrcRoot:   lastDiff.prevRoot.Hash,
					DstRound:  lastDiff.thisRoot.Round,
					DstRoot:   lastDiff.thisRoot.Hash,
					WriteLog:  lastDiff.writeLog,
				})
				if err != nil {
					n.logger.Error("can't apply write log",
						"err", err,
						"old_root", lastDiff.prevRoot,
						"new_root", lastDiff.thisRoot,
					)
				}
			}

			// Check if we have fully synced the given round. If we have, we can proceed
			// with the Finalize operation.
			syncing := syncingRounds[lastDiff.round]
			syncing.outstanding &= ^lastDiff.fetchMask
			if syncing.outstanding == maskNone && syncing.awaitingRetry == maskNone {
				n.logger.Debug("finished syncing round", "round", lastDiff.round)
				delete(syncingRounds, lastDiff.round)
				summary := hashCache[lastDiff.round]
				delete(hashCache, lastDiff.round-1)

				// Finalize storage for this round. This happens asynchronously
				// with respect to Apply operations for subsequent rounds.
				lastFullyAppliedRound = lastDiff.round
				heap.Push(outOfOrderApplieds, summary)
			}

			continue
		}

		// Check if any new rounds were fully applied and need to be finalized. Only finalize
		// if it's the round after the one that was finalized last (cachedLastRound).
		// The finalization happens asynchronously with respect to this worker loop and any
		// applies that happen for subsequent rounds (which can proceed while earlier rounds are
		// still finalizing).
		if len(*outOfOrderApplieds) > 0 && cachedLastRound+1 == (*outOfOrderApplieds)[0].GetRound() {
			lastSummary := heap.Pop(outOfOrderApplieds).(*blockSummary)
			fetcherGroup.Add(1)
			go func() {
				defer fetcherGroup.Done()
				n.finalize(lastSummary)
			}()
			continue
		}

		select {
		case inBlk := <-n.blockCh.Out():
			blk := inBlk.(*block.Block)
			n.logger.Debug("incoming block",
				"round", blk.Header.Round,
				"last_synced", cachedLastRound,
			)

			if _, ok := hashCache[cachedLastRound]; !ok && cachedLastRound == n.undefinedRound {
				dummy := blockSummary{
					Namespace: blk.Header.Namespace,
					Round:     cachedLastRound + 1,
				}
				dummy.IORoot.Empty()
				dummy.IORoot.Round = cachedLastRound + 1
				dummy.StateRoot.Empty()
				dummy.StateRoot.Round = cachedLastRound + 1
				hashCache[cachedLastRound] = &dummy
			}
			// Determine if we need to fetch any old block summaries. In case the first
			// round is an undefined round, we need to start with the following round
			// since the undefined round may be unsigned -1 and in this case the loop
			// would not do any iterations.
			startSummaryRound := cachedLastRound
			if startSummaryRound == n.undefinedRound {
				startSummaryRound++
			}
			for i := startSummaryRound; i < blk.Header.Round; i++ {
				if _, ok := hashCache[i]; ok {
					continue
				}
				var oldBlock *block.Block
				oldBlock, err = n.commonNode.Runtime.History().GetBlock(n.ctx, i)
				if err != nil {
					n.logger.Error("can't get block for round",
						"err", err,
						"round", i,
						"current_round", blk.Header.Round,
					)
					panic("can't get block in storage worker")
				}
				hashCache[i] = summaryFromBlock(oldBlock)
			}
			if _, ok := hashCache[blk.Header.Round]; !ok {
				hashCache[blk.Header.Round] = summaryFromBlock(blk)
			}

			for i := cachedLastRound + 1; i <= blk.Header.Round; i++ {
				syncing, ok := syncingRounds[i]
				if ok && syncing.outstanding == maskAll {
					continue
				}

				if !ok {
					syncing = &inFlight{
						outstanding:   maskNone,
						awaitingRetry: maskAll,
					}
					syncingRounds[i] = syncing
				}
				n.logger.Debug("preparing round sync",
					"round", i,
					"outstanding_mask", syncing.outstanding,
					"awaiting_retry", syncing.awaitingRetry,
				)

				prev := hashCache[i-1] // Closures take refs, so they need new variables here.
				this := hashCache[i]
				prevIORoot := urkelNode.Root{ // IO roots aren't chained, so clear it (but leave cache intact).
					Namespace: this.IORoot.Namespace,
					Round:     this.IORoot.Round,
				}
				prevIORoot.Hash.Empty()

				if (syncing.outstanding&maskIO) == 0 && (syncing.awaitingRetry&maskIO) != 0 {
					syncing.outstanding |= maskIO
					syncing.awaitingRetry &= ^maskIO
					fetcherGroup.Add(1)
					n.fetchPool.Submit(func() {
						defer fetcherGroup.Done()
						n.fetchDiff(this.Round, &prevIORoot, &this.IORoot, maskIO)
					})
				}
				if (syncing.outstanding&maskState) == 0 && (syncing.awaitingRetry&maskState) != 0 {
					syncing.outstanding |= maskState
					syncing.awaitingRetry &= ^maskState
					fetcherGroup.Add(1)
					n.fetchPool.Submit(func() {
						defer fetcherGroup.Done()
						n.fetchDiff(this.Round, &prev.StateRoot, &this.StateRoot, maskState)
					})
				}
			}

		case item := <-n.diffCh:
			if item.err != nil {
				n.logger.Error("error calling getdiff",
					"err", item.err,
					"round", item.round,
					"old_root", item.prevRoot,
					"new_root", item.thisRoot,
					"fetch_mask", item.fetchMask,
				)
				syncingRounds[item.round].outstanding &= ^item.fetchMask
				syncingRounds[item.round].awaitingRetry |= item.fetchMask
			} else {
				heap.Push(outOfOrderDiffs, item)
			}

		case finalized := <-n.finalizeCh:
			// No further sync or out of order handling needed here, since
			// only one finalize at a time is triggered (for round cachedLastRound+1)
			n.syncedLock.Lock()
			n.syncedState.LastBlock.Round = finalized.Round
			n.syncedState.LastBlock.IORoot = finalized.IORoot
			n.syncedState.LastBlock.StateRoot = finalized.StateRoot
			rtID := n.commonNode.Runtime.ID()
			err = n.stateStore.PutCBOR(rtID[:], &n.syncedState)
			n.syncedLock.Unlock()
			cachedLastRound = finalized.Round
			if err != nil {
				n.logger.Error("can't store watcher state to database", "err", err)
			}

		case <-n.ctx.Done():
			break mainLoop
		}
	}

	fetcherGroup.Wait()
	// blockCh will be garbage-collected without being closed. It can potentially still contain
	// some new blocks, but only as many as were already in-flight at the point when the main
	// context was canceled.
}

type pruneHandler struct {
	logger    *logging.Logger
	node      *Node
	namespace common.Namespace
}

func (p *pruneHandler) Prune(ctx context.Context, rounds []uint64) error {
	// Make sure we never prune past what was synced.
	lastSycnedRound, _, _ := p.node.GetLastSynced()

	for _, round := range rounds {
		if round >= lastSycnedRound {
			return fmt.Errorf("worker/storage: tried to prune past last synced round (last synced: %d)",
				lastSycnedRound,
			)
		}

		p.logger.Debug("pruning storage for round", "round", round)

		// Prune given block.
		if _, err := p.node.localStorage.Prune(ctx, p.namespace, round); err != nil {
			p.logger.Error("failed to prune block",
				"err", err,
			)
			return err
		}
	}

	return nil
}
