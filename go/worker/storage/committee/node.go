package committee

import (
	"container/heap"
	"context"
	"errors"
	"sync"

	"github.com/eapache/channels"

	bolt "github.com/etcd-io/bbolt"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/workerpool"
	roothashApi "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/storage"
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
	namespace common.Namespace
	round     uint64
	ioRoot    urkelNode.Root
	stateRoot urkelNode.Root
}

func summaryFromBlock(blk *block.Block) *blockSummary {
	return &blockSummary{
		namespace: blk.Header.Namespace,
		round:     blk.Header.Round,
		ioRoot: urkelNode.Root{
			Namespace: blk.Header.Namespace,
			Round:     blk.Header.Round,
			Hash:      blk.Header.IORoot,
		},
		stateRoot: urkelNode.Root{
			Namespace: blk.Header.Namespace,
			Round:     blk.Header.Round,
			Hash:      blk.Header.StateRoot,
		},
	}
}

type watcherState struct {
	lastBlock blockSummary
}

// Node watches blocks for storage changes.
type Node struct {
	commonNode *committee.Node

	logger *logging.Logger

	localStorage      storageApi.LocalBackend
	storageClient     storageApi.ClientBackend
	storageGrpcServer *storage.GrpcServer
	undefinedRound    uint64

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
	storageGrpcServer *storage.GrpcServer,
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

		localStorage:      localStorage,
		storageGrpcServer: storageGrpcServer,

		fetchPool: fetchPool,

		stateStore: db,
		bucketName: bucket,

		blockCh: channels.NewInfiniteChannel(),
		diffCh:  make(chan *fetchedDiff),

		quitCh: make(chan struct{}),
		initCh: make(chan struct{}),
	}

	node.syncedState.lastBlock.round = defaultUndefinedRound
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

	scl, err := client.New(node.ctx, node.commonNode.Identity.TLSCertificate, node.commonNode.Scheduler, node.commonNode.Registry)
	if err != nil {
		return nil, err
	}
	node.storageClient = scl.(storageApi.ClientBackend)

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
func (n *Node) HandleEpochTransitionLocked(*committee.EpochSnapshot) {
	// Nothing to do here.
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

	return n.syncedState.lastBlock.round, n.syncedState.lastBlock.ioRoot.Hash, n.syncedState.lastBlock.stateRoot.Hash
}

func (n *Node) fetchDiff(round uint64, prevRoot *urkelNode.Root, thisRoot *urkelNode.Root) error {
	var writeLog storageApi.WriteLog
	if !n.localStorage.HasRoot(*thisRoot) {
		n.logger.Debug("calling GetDiff", "previous_root", prevRoot, "root", thisRoot)
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
	n.diffCh <- &fetchedDiff{
		round:    round,
		prevRoot: *prevRoot,
		thisRoot: *thisRoot,
		writeLog: writeLog,
	}
	return nil
}

type inFlight struct {
	outstanding map[hash.Hash]struct{}
}

func (n *Node) worker() {
	defer close(n.quitCh)
	defer close(n.diffCh)

	genesisBlock, err := n.commonNode.Roothash.GetGenesisBlock(n.ctx, n.commonNode.RuntimeID)
	if err != nil {
		n.logger.Error("can't retrieve genesis block", "err", err)
		panic("can't retrieve genesis block")
	}
	n.undefinedRound = genesisBlock.Header.Round - 1

	var fetcherGroup sync.WaitGroup

	n.syncedLock.RLock()
	cachedLastRound := n.syncedState.lastBlock.round
	n.syncedLock.RUnlock()
	if cachedLastRound == defaultUndefinedRound {
		cachedLastRound = n.undefinedRound
	}

	outOfOrderDone := &outOfOrderQueue{}
	syncingRounds := make(map[uint64]*inFlight)
	hashCache := make(map[uint64]*blockSummary)

	heap.Init(outOfOrderDone)

	close(n.initCh)

mainLoop:
	for {
		if len(*outOfOrderDone) > 0 && cachedLastRound+1 == (*outOfOrderDone)[0].round {
			lastDiff := heap.Pop(outOfOrderDone).(*fetchedDiff)
			// Check if we already had the writelog and apply it if not.
			if lastDiff.writeLog != nil {
				_, err := n.localStorage.Apply(n.ctx, lastDiff.thisRoot.Namespace,
					lastDiff.prevRoot.Round, lastDiff.prevRoot.Hash,
					lastDiff.thisRoot.Round, lastDiff.thisRoot.Hash,
					lastDiff.writeLog)
				if err != nil {
					n.logger.Error("can't apply write log", "err", err)
				}
			}

			delete(syncingRounds[lastDiff.round].outstanding, lastDiff.thisRoot.Hash)
			if len(syncingRounds[lastDiff.round].outstanding) == 0 {
				delete(syncingRounds, lastDiff.round)
				summary := hashCache[lastDiff.round]
				delete(hashCache, lastDiff.round-1)

				n.syncedLock.Lock()
				n.syncedState.lastBlock.round = lastDiff.round
				n.syncedState.lastBlock.ioRoot = summary.ioRoot
				n.syncedState.lastBlock.stateRoot = summary.stateRoot
				err := n.stateStore.Update(func(tx *bolt.Tx) error {
					bkt := tx.Bucket(n.bucketName)
					bytes := cbor.Marshal(n.syncedState)
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
		case inBlk := <-n.blockCh.Out():
			blk := inBlk.(*block.Block)
			n.logger.Debug("incoming block", "round", blk.Header.Round)

			if _, ok := hashCache[cachedLastRound]; !ok && cachedLastRound == n.undefinedRound {
				dummy := blockSummary{
					namespace: blk.Header.Namespace,
					round:     cachedLastRound,
				}
				dummy.ioRoot.Empty()
				dummy.stateRoot.Empty()
				hashCache[cachedLastRound] = &dummy
			}
			for i := cachedLastRound + 1; i < blk.Header.Round; i++ {
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

				newSync := &inFlight{
					outstanding: make(map[hash.Hash]struct{}),
				}
				hashes := hashCache[i]
				newSync.outstanding[hashes.ioRoot.Hash] = struct{}{}
				newSync.outstanding[hashes.stateRoot.Hash] = struct{}{}
				syncingRounds[i] = newSync

				prev := hashCache[i-1] // Closures take refs, so they need new variables here.
				this := hashCache[i]
				prevIORoot := urkelNode.Root{ // IO roots aren't chained, so clear it (but leave cache intact).
					Namespace: this.ioRoot.Namespace,
					Round:     this.ioRoot.Round,
				}
				prevIORoot.Hash.Empty()
				fetcherGroup.Add(1)
				n.fetchPool.Submit(func() {
					defer fetcherGroup.Done()

					err := n.fetchDiff(this.round, &prevIORoot, &this.ioRoot)
					if err != nil {
						n.logger.Error("error getting block io difference to round", "err", err, "round", this.round)
					}
				})
				fetcherGroup.Add(1)
				n.fetchPool.Submit(func() {
					defer fetcherGroup.Done()

					err := n.fetchDiff(this.round, &prev.stateRoot, &this.stateRoot)
					if err != nil {
						n.logger.Error("error getting block state difference to round", "err", err, "round", this.round)
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
