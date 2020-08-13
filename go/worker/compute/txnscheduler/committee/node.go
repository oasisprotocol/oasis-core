package committee

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/tracing"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	runtimeCommittee "github.com/oasisprotocol/oasis-core/go/runtime/committee"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	executorCommittee "github.com/oasisprotocol/oasis-core/go/worker/compute/executor/committee"
	txnSchedulerAlgorithm "github.com/oasisprotocol/oasis-core/go/worker/compute/txnscheduler/algorithm"
	txnSchedulerAlgorithmApi "github.com/oasisprotocol/oasis-core/go/worker/compute/txnscheduler/algorithm/api"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/txnscheduler/api"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

var (
	errIncorrectState = errors.New("incorrect state")
	errNoBlocks       = errors.New("no blocks")
)

var (
	incomingQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_txnscheduler_incoming_queue_size",
			Help: "Size of the incoming queue (number of entries).",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		incomingQueueSize,
	}

	metricsOnce sync.Once
)

// Node is a committee node.
type Node struct { // nolint: maligned
	*commonWorker.RuntimeHostNode

	checkTxEnabled bool

	commonNode   *committee.Node
	executorNode *executorCommittee.Node

	roleProvider registration.RoleProvider

	// The algorithm mutex is here to protect the initialization
	// of the algorithm variable. After initialization the variable
	// will never change though -- so if the variable is non-nil
	// (which must be checked while holding the read lock) it can
	// safely be used without holding the lock.
	algorithmMutex sync.RWMutex
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

// CheckTx checks the given call in the node's runtime.
func (n *Node) CheckTx(ctx context.Context, call []byte) error {
	n.commonNode.CrossNode.Lock()
	currentBlock := n.commonNode.CurrentBlock
	n.commonNode.CrossNode.Unlock()

	if currentBlock == nil {
		return api.ErrNotReady
	}

	checkRq := &protocol.Body{
		RuntimeCheckTxBatchRequest: &protocol.RuntimeCheckTxBatchRequest{
			Inputs: transaction.RawBatch{call},
			Block:  *currentBlock,
		},
	}
	rt := n.GetHostedRuntime()
	if rt == nil {
		n.logger.Error("hosted runtime not initialized")
		return api.ErrNotReady
	}
	resp, err := rt.Call(ctx, checkRq)
	if err != nil {
		n.logger.Error("runtime CheckTx call error",
			"err", err,
		)
		return err
	}
	if resp == nil {
		n.logger.Error("runtime CheckTx response is nil")
		return api.ErrCheckTxFailed
	}
	if resp.RuntimeCheckTxBatchResponse.Results == nil {
		n.logger.Error("runtime CheckTx response contains no results")
		return api.ErrCheckTxFailed
	}
	if len(resp.RuntimeCheckTxBatchResponse.Results) != 1 {
		n.logger.Error("runtime CheckTx response doesn't contain exactly one result",
			"num_results", len(resp.RuntimeCheckTxBatchResponse.Results),
		)
		return api.ErrCheckTxFailed
	}

	// Interpret CheckTx result.
	resultRaw := resp.RuntimeCheckTxBatchResponse.Results[0]
	var result transaction.TxnOutput
	if err = cbor.Unmarshal(resultRaw, &result); err != nil {
		n.logger.Error("runtime CheckTx response failed to deserialize",
			"err", err,
		)
		return api.ErrCheckTxFailed
	}
	if result.Error != nil {
		n.logger.Error("runtime CheckTx failed with error",
			"err", result.Error,
		)
		return fmt.Errorf("%w: %s", api.ErrCheckTxFailed, *result.Error)
	}

	return nil
}

// QueueCall queues a call for processing by this node.
func (n *Node) QueueCall(ctx context.Context, expectedEpochNumber epochtime.EpochTime, call []byte) error {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	epochSnapshot := n.commonNode.Group.GetEpochSnapshot()
	if !epochSnapshot.IsTransactionSchedulerLeader() {
		return api.ErrNotLeader
	}
	// Check if expected client's epoch matches the current worker's one.
	if epochSnapshot.GetEpochNumber() != expectedEpochNumber {
		n.logger.Error("unable to QueueCall",
			"err", api.ErrEpochNumberMismatch,
			"current_epoch_number", epochSnapshot.GetEpochNumber(),
			"expected_epoch_number", expectedEpochNumber,
		)
		return api.ErrEpochNumberMismatch
	}

	if n.checkTxEnabled {
		// Check transaction before queuing it.
		if err := n.CheckTx(ctx, call); err != nil {
			return err
		}
		n.logger.Debug("worker CheckTx successful, queuing transaction")
	}

	n.algorithmMutex.RLock()
	defer n.algorithmMutex.RUnlock()

	if n.algorithm == nil || !n.algorithm.IsInitialized() {
		return api.ErrNotReady
	}
	if err := n.algorithm.ScheduleTx(call); err != nil {
		return err
	}

	incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.algorithm.UnscheduledSize()))

	return nil
}

// IsTransactionQueued checks if the given transaction is present in the
// transaction scheduler queue and is waiting to be dispatched to a
// executor committee.
func (n *Node) IsTransactionQueued(ctx context.Context, id hash.Hash) (bool, error) {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.commonNode.Group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
		return false, api.ErrNotLeader
	}

	n.algorithmMutex.RLock()
	defer n.algorithmMutex.RUnlock()

	if n.algorithm == nil || !n.algorithm.IsInitialized() {
		return false, api.ErrNotReady
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
	n.algorithmMutex.RLock()
	if n.algorithm == nil || !n.algorithm.IsInitialized() {
		n.logger.Error("scheduling algorithm not available yet")
		n.algorithmMutex.RUnlock()
		return
	}
	n.algorithmMutex.RUnlock()

	if epoch.IsTransactionSchedulerLeader() {
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
	// Nothing to do here.
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
	// Nothing to do here.
}

// HandleNodeUpdateLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNodeUpdateLocked(update *runtimeCommittee.NodeUpdate, snapshot *committee.EpochSnapshot) {
	// Nothing to do here.
}

// Dispatch dispatches a batch to the executor committee.
func (n *Node) Dispatch(batch transaction.RawBatch) error {
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
	// tags will be added later by the executor nodes).
	emptyRoot := storage.Root{
		Namespace: lastHeader.Namespace,
		Version:   lastHeader.Round + 1,
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

	dispatchMsg := &commitment.TxnSchedulerBatch{
		IORoot:            ioRoot,
		StorageSignatures: ioReceiptSignatures,
		Header:            n.commonNode.CurrentBlock.Header,
	}
	signedDispatchMsg, err := commitment.SignTxnSchedulerBatch(n.commonNode.Identity.NodeSigner, dispatchMsg)
	if err != nil {
		n.logger.Error("failed to sign txn scheduler batch",
			"err", err,
		)
		return fmt.Errorf("failed to sign txn scheduler batch: %w", err)
	}

	err = n.commonNode.Group.Publish(
		batchSpanCtx,
		&p2p.Message{
			TxnSchedulerBatch: signedDispatchMsg,
		},
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

	if epoch.IsExecutorMember() {
		if n.executorNode == nil {
			n.logger.Error("scheduler says we are a executor worker, but we are not")
		} else {
			n.executorNode.HandleBatchFromTransactionSchedulerLocked(
				batchSpanCtx,
				ioRoot,
				batch,
				signedDispatchMsg.Signature,
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

	var hrtEventCh <-chan *host.Event
	if n.checkTxEnabled {
		// Provision hosted runtime.
		hrt, hrtNotifier, err := n.ProvisionHostedRuntime(n.ctx)
		if err != nil {
			n.logger.Error("failed to provision hosted runtime",
				"err", err,
			)
			return
		}

		var hrtSub pubsub.ClosableSubscription
		hrtEventCh, hrtSub, err = hrt.WatchEvents(n.ctx)
		if err != nil {
			n.logger.Error("failed to subscribe to hosted runtime events",
				"err", err,
			)
			return
		}
		defer hrtSub.Close()

		if err = hrt.Start(); err != nil {
			n.logger.Error("failed to start hosted runtime",
				"err", err,
			)
			return
		}
		defer hrt.Stop()

		if err = hrtNotifier.Start(); err != nil {
			n.logger.Error("failed to start runtime notifier",
				"err", err,
			)
			return
		}
		defer hrtNotifier.Stop()
	}

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
		n.logger.Error("failed to create new transaction scheduler algorithm",
			"err", err,
		)
		return
	}
	if err := txnAlgorithm.Initialize(n); err != nil {
		n.logger.Error("failed initializing transaction scheduler algorithm",
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

	if !n.checkTxEnabled {
		// We are now ready to service requests.
		n.roleProvider.SetAvailable(func(*node.Node) error { return nil })
	}

	for {
		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case ev := <-hrtEventCh:
			switch {
			case ev.Started != nil, ev.Updated != nil:
				// We are now able to service requests for this runtime.
				n.roleProvider.SetAvailable(func(*node.Node) error { return nil })
			case ev.FailedToStart != nil, ev.Stopped != nil:
				// Runtime failed to start or was stopped -- we can no longer service requests.
				n.roleProvider.SetUnavailable()
			default:
				// Unknown event.
				n.logger.Warn("unknown worker event",
					"ev", ev,
				)
			}
		case <-scheduleTicker.C:
			// Flush a batch from algorithm.
			n.algorithm.Flush()
		}
	}
}

func NewNode(
	commonNode *committee.Node,
	executorNode *executorCommittee.Node,
	checkTxEnabled bool,
	commonCfg commonWorker.Config,
	roleProvider registration.RoleProvider,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	// Prepare the runtime host node helpers.
	rhn, err := commonWorker.NewRuntimeHostNode(commonCfg.RuntimeHost, commonNode)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		RuntimeHostNode:  rhn,
		checkTxEnabled:   checkTxEnabled,
		commonNode:       commonNode,
		executorNode:     executorNode,
		roleProvider:     roleProvider,
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
