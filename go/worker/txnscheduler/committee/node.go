package committee

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/oasis-core/go/common/crash"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/tracing"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/worker/common/committee"
	"github.com/oasislabs/oasis-core/go/worker/common/p2p"
	computeCommittee "github.com/oasislabs/oasis-core/go/worker/compute/committee"
	txnSchedulerAlgorithm "github.com/oasislabs/oasis-core/go/worker/txnscheduler/algorithm"
	txnSchedulerAlgorithmApi "github.com/oasislabs/oasis-core/go/worker/txnscheduler/algorithm/api"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/api"
)

var (
	errIncorrectState = errors.New("incorrect state")
	errNoBlocks       = errors.New("no blocks")
)

var (
	incomingQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_txnscheduler_incoming_queue_size",
			Help: "Size of the incoming queue (number of entries)",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		incomingQueueSize,
	}

	metricsOnce sync.Once
)

// Node is a committee node.
type Node struct {
	commonNode  *committee.Node
	computeNode *computeCommittee.Node

	algorithmMutex sync.Mutex
	algorithm      txnSchedulerAlgorithmApi.Algorithm

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	stopOnce  sync.Once
	quitCh    chan struct{}
	initCh    chan struct{}

	// Mutable and shared with common node's worker.
	// Guarded by .commonNode.CrossNode.
	state NodeState

	stateTransitions *pubsub.Broker

	logger *logging.Logger
}

// Name returns the service name.
func (n *Node) Name() string {
	return "committee node"
}

// Start starts the service.
func (n *Node) Start() error {
	go n.worker()
	return nil
}

// Stop halts the service.
func (n *Node) Stop() {
	n.stopOnce.Do(func() { close(n.stopCh) })
}

// Quit returns a channel that will be closed when the service terminates.
func (n *Node) Quit() <-chan struct{} {
	return n.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (n *Node) Cleanup() {
}

// Initialized returns a channel that will be closed when the node is
// initialized and ready to service requests.
func (n *Node) Initialized() <-chan struct{} {
	return n.initCh
}

// WatchStateTransitions subscribes to the node's state transitions.
func (n *Node) WatchStateTransitions() (<-chan NodeState, *pubsub.Subscription) {
	sub := n.stateTransitions.Subscribe()
	ch := make(chan NodeState)
	sub.Unwrap(ch)

	return ch, sub
}

func (n *Node) getMetricLabels() prometheus.Labels {
	return prometheus.Labels{
		"runtime": n.commonNode.Runtime.ID().String(),
	}
}

// HandlePeerMessage implements NodeHooks.
func (n *Node) HandlePeerMessage(ctx context.Context, message *p2p.Message) (bool, error) {
	return false, nil
}

// QueueCall queues a call for processing by this node.
func (n *Node) QueueCall(ctx context.Context, call []byte) error {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.commonNode.Group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
		return api.ErrNotLeader
	}

	if err := n.algorithm.ScheduleTx(call); err != nil {
		return err
	}

	incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.algorithm.UnscheduledSize()))

	return nil
}

// IsTransactionQueued checks if the given transaction is present in the
// transaction scheduler queue and is waiting to be dispatched to a
// compute committee.
func (n *Node) IsTransactionQueued(ctx context.Context, id hash.Hash) (bool, error) {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.commonNode.Group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
		return false, api.ErrNotLeader
	}

	return n.algorithm.IsQueued(id), nil
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) transitionLocked(state NodeState) {
	n.logger.Info("state transition",
		"current_state", n.state,
		"new_state", state,
	)

	// Validate state transition.
	dests := validStateTransitions[n.state.Name()]

	var valid bool
	for _, dest := range dests[:] {
		if dest == state.Name() {
			valid = true
			break
		}
	}

	if !valid {
		panic(fmt.Sprintf("invalid state transition: %s -> %s", n.state, state))
	}

	n.state = state
	n.stateTransitions.Broadcast(state)
}

// HandleEpochTransitionLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleEpochTransitionLocked(epoch *committee.EpochSnapshot) {
	n.algorithmMutex.Lock()
	if n.algorithm == nil || !n.algorithm.IsInitialized() {
		n.logger.Error("scheduling algorithm not available yet")
		n.algorithmMutex.Unlock()
		return
	}
	n.algorithmMutex.Unlock()

	if epoch.IsTransactionSchedulerLeader() {
		if err := n.algorithm.EpochTransition(epoch); err != nil {
			n.logger.Error("scheduling algorithm failed to process epoch transition",
				"err", err,
			)
			n.transitionLocked(StateNotReady{})
			return
		}

		n.transitionLocked(StateWaitingForBatch{})
	} else {
		n.algorithm.Clear()
		// Clear incoming queue if we are not a leader.
		incomingQueueSize.With(n.getMetricLabels()).Set(0)
		n.transitionLocked(StateNotReady{})
	}
	// TODO: Make non-leader members follow.
}

// HandleNewBlockEarlyLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(blk *block.Block) {
}

// HandleNewBlockLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockLocked(blk *block.Block) {
	// Perform actions based on current state.
	switch n.state.(type) {
	case StateWaitingForFinalize:
		// A new block means the round has been finalized.
		n.logger.Info("considering the round finalized")
		n.transitionLocked(StateWaitingForBatch{})
	}
}

// HandleNewEventLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewEventLocked(ev *roothash.Event) {
}

// Dispatch dispatches a batch to the compute committee.
func (n *Node) Dispatch(committeeID hash.Hash, batch transaction.RawBatch) error {
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	// If we are not waiting for a batch, don't do anything.
	if _, ok := n.state.(StateWaitingForBatch); !ok {
		return errIncorrectState
	}

	epoch := n.commonNode.Group.GetEpochSnapshot()
	// If we are not a leader or we don't have any blocks, don't do anything.
	if !epoch.IsTransactionSchedulerLeader() {
		return api.ErrNotLeader
	}
	if n.commonNode.CurrentBlock == nil {
		return errNoBlocks
	}

	lastHeader := n.commonNode.CurrentBlock.Header

	// Leader node opens a new parent span for batch processing.
	batchSpan := opentracing.StartSpan("TakeBatchFromQueue(batch)")
	defer batchSpan.Finish()
	batchSpanCtx := batchSpan.Context()

	// Generate the initial I/O root containing only the inputs (outputs and
	// tags will be added later by the compute nodes).
	emptyRoot := storage.Root{
		Namespace: lastHeader.Namespace,
		Round:     lastHeader.Round + 1,
	}
	emptyRoot.Hash.Empty()

	ioTree := transaction.NewTree(nil, emptyRoot)
	defer ioTree.Close()

	for idx, tx := range batch {
		if err := ioTree.AddTransaction(n.ctx, transaction.Transaction{Input: tx, BatchOrder: uint32(idx)}, nil); err != nil {
			n.logger.Error("failed to create I/O tree",
				"err", err,
			)
			return err
		}
	}

	ioWriteLog, ioRoot, err := ioTree.Commit(n.ctx)
	if err != nil {
		n.logger.Error("failed to create I/O tree",
			"err", err,
		)
		return err
	}

	// Commit I/O tree to storage and obtain receipts.
	spanInsert, ctx := tracing.StartSpanWithContext(n.ctx, "Apply(ioWriteLog)",
		opentracing.ChildOf(batchSpanCtx),
	)

	ioReceipts, err := n.commonNode.Storage.Apply(ctx, &storage.ApplyRequest{
		Namespace: lastHeader.Namespace,
		SrcRound:  lastHeader.Round + 1,
		SrcRoot:   emptyRoot.Hash,
		DstRound:  lastHeader.Round + 1,
		DstRoot:   ioRoot,
		WriteLog:  ioWriteLog,
	})
	if err != nil {
		spanInsert.Finish()
		n.logger.Error("failed to commit I/O tree to storage",
			"err", err,
		)
		return err
	}
	spanInsert.Finish()

	// Dispatch batch to group.
	spanPublish := opentracing.StartSpan("PublishScheduledBatch(batchHash, header)",
		opentracing.Tag{Key: "ioRoot", Value: ioRoot},
		opentracing.Tag{Key: "header", Value: n.commonNode.CurrentBlock.Header},
		opentracing.ChildOf(batchSpanCtx),
	)
	ioReceiptSignatures := []signature.Signature{}
	for _, receipt := range ioReceipts {
		ioReceiptSignatures = append(ioReceiptSignatures, receipt.Signature)
	}
	txnSchedSig, err := n.commonNode.Group.PublishScheduledBatch(
		batchSpanCtx,
		committeeID,
		ioRoot,
		ioReceiptSignatures,
		n.commonNode.CurrentBlock.Header,
	)
	if err != nil {
		spanPublish.Finish()
		n.logger.Error("failed to publish batch to committee",
			"err", err,
		)
		return err
	}
	crash.Here(crashPointLeaderBatchPublishAfter)
	spanPublish.Finish()

	n.transitionLocked(StateWaitingForFinalize{})

	if epoch.IsComputeMember() {
		if n.computeNode == nil {
			n.logger.Error("scheduler says we are a compute worker, but we are not")
		} else {
			n.computeNode.HandleBatchFromTransactionSchedulerLocked(
				batchSpanCtx,
				committeeID,
				ioRoot,
				batch,
				*txnSchedSig,
				ioReceiptSignatures,
			)
		}
	}

	return nil
}

func (n *Node) worker() {
	defer close(n.quitCh)
	defer (n.cancelCtx)()

	// Wait for the common node to be initialized.
	select {
	case <-n.commonNode.Initialized():
	case <-n.stopCh:
		close(n.initCh)
		return
	}

	n.logger.Info("starting committee node")

	// Initialize transaction scheduler's algorithm.
	runtime, err := n.commonNode.Runtime.RegistryDescriptor(n.ctx)
	if err != nil {
		n.logger.Error("failed to fetch runtime registry descriptor",
			"err", err,
		)
		return
	}
	txnAlgorithm, err := txnSchedulerAlgorithm.New(
		runtime.TxnScheduler.Algorithm,
		runtime.TxnScheduler.MaxBatchSize,
		runtime.TxnScheduler.MaxBatchSizeBytes,
	)
	if err != nil {
		n.logger.Error("Failed to create new transaction scheduler algorithm",
			"err", err,
		)
		return
	}
	if err := txnAlgorithm.Initialize(n); err != nil {
		n.logger.Error("Failed initializing transaction scheduler algorithm",
			"err", err,
		)
		return
	}

	n.algorithmMutex.Lock()
	n.algorithm = txnAlgorithm
	n.algorithmMutex.Unlock()

	// Check incoming queue every FlushTimeout.
	scheduleTicker := time.NewTicker(runtime.TxnScheduler.BatchFlushTimeout)
	defer scheduleTicker.Stop()

	// We are initialized.
	close(n.initCh)

	for {
		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case <-scheduleTicker.C:
			// Flush a batch from algorithm.
			n.algorithm.Flush()
		}
	}
}

func NewNode(
	commonNode *committee.Node,
	computeNode *computeCommittee.Node,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		commonNode:       commonNode,
		computeNode:      computeNode,
		ctx:              ctx,
		cancelCtx:        cancel,
		stopCh:           make(chan struct{}),
		quitCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		state:            StateNotReady{},
		stateTransitions: pubsub.NewBroker(false),
		logger:           logging.GetLogger("worker/txnscheduler/committee").With("runtime_id", commonNode.Runtime.ID()),
	}

	return n, nil
}
