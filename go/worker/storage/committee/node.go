package committee

import (
	"container/heap"
	"context"
	"errors"
	"sync"

	"github.com/eapache/channels"

	bolt "github.com/etcd-io/bbolt"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/accessctl"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/grpc"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/common/workerpool"
	roothashApi "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	storageApi "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/client"
	urkelNode "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
)

var (
	_ committee.NodeHooks = (*Node)(nil)

	// ErrNonLocalBackend is the error returned when the storage backend doesn't implement the LocalBackend interface.
	ErrNonLocalBackend = errors.New("storage: storage backend doesn't support local storage")
)

const (
	defaultUndefinedRound = ^uint64(0)
)

// Syncing task context and support functions for container/heap.

type fetchedDiff struct {
	round    uint64
	prevRoot urkelNode.Root
	thisRoot urkelNode.Root
	writeLog storageApi.WriteLog
}

type outOfOrderQueue []*fetchedDiff

// Sorting interface.
func (q outOfOrderQueue) Len() int           { return len(q) }
func (q outOfOrderQueue) Less(i, j int) bool { return q[i].round < q[j].round }
func (q outOfOrderQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }

// Push appends x as the last element in the heap's array.
func (q *outOfOrderQueue) Push(x interface{}) {
	*q = append(*q, x.(*fetchedDiff))
}

// Pop removes and returns the last element in the heap's array.
func (q *outOfOrderQueue) Pop() interface{} {
	old := *q
	n := len(old)
	x := old[n-1]
	*q = old[0 : n-1]
	return x
}

// Small block metadata cache.

type blockSummary struct {
	Namespace common.Namespace `codec:"namespace"`
	Round     uint64           `codec:"round"`
	IORoot    urkelNode.Root   `codec:"io_root"`
	StateRoot urkelNode.Root   `codec:"state_root"`
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
	LastBlock blockSummary `codec:"last_block"`
}

// Node watches blocks for storage changes.
type Node struct {
	commonNode *committee.Node

	logger *logging.Logger

	localStorage   storageApi.LocalBackend
	storageClient  storageApi.ClientBackend
	grpcPolicy     *grpc.DynamicRuntimePolicyChecker
	undefinedRound uint64

	fetchPool *workerpool.Pool

	stateStore *bolt.DB
	bucketName []byte

	syncedLock  sync.RWMutex
	syncedState watcherState

	blockCh *channels.InfiniteChannel
	diffCh  chan *fetchedDiff

	ctx       context.Context
	ctxCancel context.CancelFunc

	quitCh chan struct{}
	initCh chan struct{}
}

func NewNode(
	commonNode *committee.Node,
	grpcPolicy *grpc.DynamicRuntimePolicyChecker,
	fetchPool *workerpool.Pool,
	db *bolt.DB,
	bucket []byte,
) (*Node, error) {
	localStorage, ok := commonNode.Storage.(storageApi.LocalBackend)
	if !ok {
		return nil, ErrNonLocalBackend
	}

	node := &Node{
		commonNode: commonNode,

		logger: logging.GetLogger("worker/storage/committee").With("runtime_id", commonNode.RuntimeID),

		localStorage: localStorage,
		grpcPolicy:   grpcPolicy,

		fetchPool: fetchPool,

		stateStore: db,
		bucketName: bucket,

		blockCh: channels.NewInfiniteChannel(),
		diffCh:  make(chan *fetchedDiff),

		quitCh: make(chan struct{}),
		initCh: make(chan struct{}),
	}

	node.syncedState.LastBlock.Round = defaultUndefinedRound
	err := db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(bucket)

		bytes := bkt.Get(commonNode.RuntimeID[:])
		if bytes != nil {
			return cbor.Unmarshal(bytes, &node.syncedState)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	node.ctx, node.ctxCancel = context.WithCancel(context.Background())

	// Create a new storage client that will be used for remote sync.
	scl, err := client.New(node.ctx, node.commonNode.Identity.TLSCertificate, node.commonNode.Scheduler, node.commonNode.Registry)
	if err != nil {
		return nil, err
	}
	node.storageClient = scl.(storageApi.ClientBackend)
	if err := node.storageClient.WatchRuntime(commonNode.RuntimeID); err != nil {
		node.logger.Error("error watching storage runtime",
			"err", err,
		)
		return nil, err
	}

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
	for _, cc := range snapshot.GetComputeCommittees() {
		if cc != nil {
			computeCommitteePolicy.AddRulesForCommittee(&policy, cc)
		}
	}
	if tsc := snapshot.GetTransactionSchedulerCommittee(); tsc != nil {
		txnSchedulerCommitteePolicy.AddRulesForCommittee(&policy, tsc)
	}
	if mc := snapshot.GetMergeCommittee(); mc != nil {
		mergeCommitteePolicy.AddRulesForCommittee(&policy, mc)
	}
	// TODO: Query registry only for storage nodes after
	// https://github.com/oasislabs/ekiden/issues/1923 is implemented.
	nodes, err := n.commonNode.Registry.GetNodes(context.Background())
	if nodes != nil {
		storageNodesPolicy.AddRulesForNodeRoles(&policy, nodes, node.RoleStorageWorker)
	} else {
		n.logger.Error("couldn't get nodes from registry", "err", err)
	}
	// Update storage gRPC access policy for the current runtime.
	n.grpcPolicy.SetAccessPolicy(policy, n.commonNode.RuntimeID)
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
func (n *Node) GetLastSynced() (uint64, hash.Hash, hash.Hash) {
	n.syncedLock.RLock()
	defer n.syncedLock.RUnlock()

	return n.syncedState.LastBlock.Round, n.syncedState.LastBlock.IORoot.Hash, n.syncedState.LastBlock.StateRoot.Hash
}

func (n *Node) fetchDiff(round uint64, prevRoot *urkelNode.Root, thisRoot *urkelNode.Root) error {
	var writeLog storageApi.WriteLog
	// Check if the new root doesn't already exist.
	if !n.localStorage.HasRoot(*thisRoot) {
		if thisRoot.Hash.Equal(&prevRoot.Hash) {
			// Even if HasRoot returns false the root can still exist if it is equal
			// to the previous root and the root was emitted by the consensus committee
			// directly (e.g., during an epoch transition). In this case we need to
			// still apply the (empty) write log.
			writeLog = storageApi.WriteLog{}
		} else {
			// New root does not yet exist in storage and we need to fetch it from a
			// remote node.
			n.logger.Debug("calling GetDiff",
				"previous_root", prevRoot,
				"root", thisRoot,
			)

			it, err := n.storageClient.GetDiff(n.ctx, *prevRoot, *thisRoot)
			if err != nil {
				return err
			}
			for {
				more, err := it.Next()
				if err != nil {
					return err
				}
				if !more {
					break
				}

				chunk, err := it.Value()
				if err != nil {
					return err
				}
				writeLog = append(writeLog, chunk)
			}
		}
	}
	n.diffCh <- &fetchedDiff{
		round:    round,
		prevRoot: *prevRoot,
		thisRoot: *thisRoot,
		writeLog: writeLog,
	}
	return nil
}

type inFlight struct {
	outstanding int
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

	genesisBlock, err := n.commonNode.Roothash.GetGenesisBlock(n.ctx, n.commonNode.RuntimeID)
	if err != nil {
		n.logger.Error("can't retrieve genesis block", "err", err)
		return
	}
	n.undefinedRound = genesisBlock.Header.Round - 1

	// Subscribe to pruned roothash blocks.
	var pruneCh <-chan *roothashApi.PrunedBlock
	var pruneSub *pubsub.Subscription
	pruneCh, pruneSub, err = n.commonNode.Roothash.WatchPrunedBlocks()
	if err != nil {
		n.logger.Error("failed to watch pruned blocks", "err", err)
		return
	}
	defer pruneSub.Close()

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

	outOfOrderDone := &outOfOrderQueue{}
	syncingRounds := make(map[uint64]*inFlight)
	hashCache := make(map[uint64]*blockSummary)

	heap.Init(outOfOrderDone)

	close(n.initCh)

mainLoop:
	for {
		if len(*outOfOrderDone) > 0 && cachedLastRound+1 == (*outOfOrderDone)[0].round {
			lastDiff := heap.Pop(outOfOrderDone).(*fetchedDiff)
			// Apply the write log if one exists.
			if lastDiff.writeLog != nil {
				_, err := n.localStorage.Apply(n.ctx, lastDiff.thisRoot.Namespace,
					lastDiff.prevRoot.Round, lastDiff.prevRoot.Hash,
					lastDiff.thisRoot.Round, lastDiff.thisRoot.Hash,
					lastDiff.writeLog)
				if err != nil {
					n.logger.Error("can't apply write log",
						"err", err,
						"prev_root", lastDiff.prevRoot,
						"root", lastDiff.thisRoot,
					)
				}
			}

			// Check if we have synced the given round.
			syncingRounds[lastDiff.round].outstanding--
			if syncingRounds[lastDiff.round].outstanding == 0 {
				n.logger.Debug("finished syncing round", "round", lastDiff.round)

				delete(syncingRounds, lastDiff.round)
				summary := hashCache[lastDiff.round]
				delete(hashCache, lastDiff.round-1)

				// Finalize storage for this round.
				err := n.localStorage.Finalize(n.ctx, lastDiff.thisRoot.Namespace, lastDiff.round, []hash.Hash{
					summary.IORoot.Hash,
					summary.StateRoot.Hash,
				})
				switch err {
				case nil:
					n.logger.Debug("storage round finalized",
						"round", lastDiff.round,
					)
				case storageApi.ErrAlreadyFinalized:
					// This can happen if we are restoring after a roothash migration or if
					// we crashed before updating the sync state.
					n.logger.Warn("storage round already finalized",
						"round", lastDiff.round,
					)
				default:
					n.logger.Error("failed to finalize storage round",
						"err", err,
						"round", lastDiff.round,
					)
				}

				n.syncedLock.Lock()
				n.syncedState.LastBlock.Round = lastDiff.round
				n.syncedState.LastBlock.IORoot = summary.IORoot
				n.syncedState.LastBlock.StateRoot = summary.StateRoot
				err = n.stateStore.Update(func(tx *bolt.Tx) error {
					bkt := tx.Bucket(n.bucketName)
					bytes := cbor.Marshal(&n.syncedState)
					return bkt.Put(n.commonNode.RuntimeID[:], bytes)
				})
				n.syncedLock.Unlock()
				cachedLastRound = lastDiff.round
				if err != nil {
					n.logger.Error("can't store watcher state to database", "err", err)
				}
			}

			continue
		}

		select {
		case prunedBlk := <-pruneCh:
			n.logger.Debug("pruning storage for round", "round", prunedBlk.Round)

			// Prune given block.
			var ns common.Namespace
			copy(ns[:], prunedBlk.RuntimeID[:])

			if _, err := n.localStorage.Prune(n.ctx, ns, prunedBlk.Round); err != nil {
				n.logger.Error("failed to prune block",
					"err", err,
				)
				continue mainLoop
			}
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
			for i := cachedLastRound; i < blk.Header.Round; i++ {
				if _, ok := hashCache[i]; ok {
					continue
				}
				oldBlock, err := n.commonNode.Roothash.GetBlock(n.ctx, n.commonNode.RuntimeID, i)
				if err != nil {
					n.logger.Error("can't get block for round", "err", err, "round", i, "current_round", blk.Header.Round)
					panic("can't get block in storage worker")
				}
				hashCache[i] = summaryFromBlock(oldBlock)
			}
			if _, ok := hashCache[blk.Header.Round]; !ok {
				hashCache[blk.Header.Round] = summaryFromBlock(blk)
			}

			for i := cachedLastRound + 1; i <= blk.Header.Round; i++ {
				if _, ok := syncingRounds[i]; ok {
					continue
				}

				n.logger.Debug("going to sync round", "round", i)

				syncingRounds[i] = &inFlight{
					// We are syncing two roots, I/O root and state root.
					outstanding: 2,
				}

				prev := hashCache[i-1] // Closures take refs, so they need new variables here.
				this := hashCache[i]
				prevIORoot := urkelNode.Root{ // IO roots aren't chained, so clear it (but leave cache intact).
					Namespace: this.IORoot.Namespace,
					Round:     this.IORoot.Round,
				}
				prevIORoot.Hash.Empty()
				fetcherGroup.Add(1)
				n.fetchPool.Submit(func() {
					defer fetcherGroup.Done()

					err := n.fetchDiff(this.Round, &prevIORoot, &this.IORoot)
					if err != nil {
						n.logger.Error("error getting block io difference to round", "err", err, "round", this.Round)
					}
				})
				fetcherGroup.Add(1)
				n.fetchPool.Submit(func() {
					defer fetcherGroup.Done()

					err := n.fetchDiff(this.Round, &prev.StateRoot, &this.StateRoot)
					if err != nil {
						n.logger.Error("error getting block state difference to round", "err", err, "round", this.Round)
					}
				})
			}

		case item := <-n.diffCh:
			heap.Push(outOfOrderDone, item)

		case <-n.ctx.Done():
			break mainLoop
		}
	}

	fetcherGroup.Wait()
	// blockCh will be garbage-collected without being closed. It can potentially still contain
	// some new blocks, but only as many as were already in-flight at the point when the main
	// context was canceled.
}
