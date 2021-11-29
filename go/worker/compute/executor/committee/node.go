package committee

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/prometheus/client_golang/prometheus"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling"
	schedulingAPI "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/orderedmap"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

var (
	errSeenNewerBlock     = fmt.Errorf("executor: seen newer block")
	errRuntimeAborted     = fmt.Errorf("executor: runtime aborted batch processing")
	errIncompatibleHeader = p2pError.Permanent(fmt.Errorf("executor: incompatible header"))
	errBatchTooLarge      = p2pError.Permanent(fmt.Errorf("executor: batch too large"))
	errIncorrectRole      = fmt.Errorf("executor: incorrect role")
	errIncorrectState     = fmt.Errorf("executor: incorrect state")
	errMsgFromNonTxnSched = fmt.Errorf("executor: received txn scheduler dispatch msg from non-txn scheduler")

	// Transaction scheduling errors.
	errNoBlocks    = fmt.Errorf("executor: no blocks")
	errNotExecutor = fmt.Errorf("executor: not executor in this round")

	// proposeTimeoutDelay is the duration to wait before submitting the propose timeout request.
	proposeTimeoutDelay = 2 * time.Second
	// abortTimeout is the duration to wait for the runtime to abort.
	abortTimeout = 5 * time.Second
)

var (
	discrepancyDetectedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_execution_discrepancy_detected_count",
			Help: "Number of detected execute discrepancies.",
		},
		[]string{"runtime"},
	)
	abortedBatchCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_worker_aborted_batch_count",
			Help: "Number of aborted batches.",
		},
		[]string{"runtime"},
	)
	storageCommitLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_storage_commit_latency",
			Help: "Latency of storage commit calls (state + outputs) (seconds).",
		},
		[]string{"runtime"},
	)
	batchReadTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_batch_read_time",
			Help: "Time it takes to read a batch from storage (seconds).",
		},
		[]string{"runtime"},
	)
	batchProcessingTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_batch_processing_time",
			Help: "Time it takes for a batch to finalize (seconds).",
		},
		[]string{"runtime"},
	)
	batchRuntimeProcessingTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_batch_runtime_processing_time",
			Help: "Time it takes for a batch to be processed by the runtime (seconds).",
		},
		[]string{"runtime"},
	)
	batchSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_worker_batch_size",
			Help: "Number of transactions in a batch.",
		},
		[]string{"runtime"},
	)
	incomingQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "oasis_worker_incoming_queue_size",
			Help: "Size of the incoming queue (number of entries).",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		discrepancyDetectedCount,
		abortedBatchCount,
		storageCommitLatency,
		batchReadTime,
		batchProcessingTime,
		batchRuntimeProcessingTime,
		batchSize,
		incomingQueueSize,
	}

	metricsOnce sync.Once
)

// Node is a committee node.
type Node struct { // nolint: maligned
	*runtimeRegistry.RuntimeHostNode

	runtimeReady         bool
	runtimeVersion       version.Version
	runtimeCapabilityTEE *node.CapabilityTEE

	lastScheduledCache    *lru.Cache
	scheduleMaxTxPoolSize uint64

	checkTxCh    *channels.RingChannel
	checkTxQueue *orderedmap.OrderedMap

	// The scheduler mutex is here to protect the initialization
	// of the scheduler variable and updates to scheduler parameters.
	schedulerMutex sync.RWMutex
	scheduler      schedulingAPI.Scheduler
	// Guarded by schedulerMutex.
	// roundWeightLimits are the per round batch weight limits.
	roundWeightLimits map[transaction.Weight]uint64
	// limitsLastUpdate is the round of the last update of the round weight limits.
	limitsLastUpdate uint64
	// schedulerAlgorithm is the scheduler algorithm.
	schedulerAlgorithm string

	// Guarded by .commonNode.CrossNode.
	proposingTimeout bool
	prevEpochWorker  bool

	commonNode   *committee.Node
	commonCfg    commonWorker.Config
	roleProvider registration.RoleProvider

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	stopOnce  sync.Once
	quitCh    chan struct{}
	initCh    chan struct{}

	// Mutable and shared with common node's worker.
	// Guarded by .commonNode.CrossNode.
	state NodeState
	// Context valid until the next round.
	// Guarded by .commonNode.CrossNode.
	roundCtx       context.Context
	roundCancelCtx context.CancelFunc

	storage storage.LocalBackend

	stateTransitions *pubsub.Broker
	// Bump this when we need to change what the worker selects over.
	reselect chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (n *Node) Name() string {
	return "committee node"
}

// Start starts the service.
func (n *Node) Start() error {
	// Make sure we are running with a compatible storage backend.
	lsb, ok := n.commonNode.Runtime.Storage().(storage.LocalBackend)
	if !ok {
		return fmt.Errorf("executor requires a local storage backend")
	}
	// Make sure to unwrap the local backend as we need the raw local backend here.
	if wrapped, ok := lsb.(storage.WrappedLocalBackend); ok {
		lsb = wrapped.Unwrap()
	}
	n.storage = lsb

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

// Assumes scheduler is initialized.
func (n *Node) clearQueuedTxs() {
	n.scheduler.Clear()
	if n.lastScheduledCache != nil {
		n.lastScheduledCache.Clear()
	}
	incomingQueueSize.With(n.getMetricLabels()).Set(0)
}

// HandlePeerMessage implements NodeHooks.
func (n *Node) HandlePeerMessage(ctx context.Context, message *p2p.Message, isOwn bool) (bool, error) {
	n.logger.Debug("received peer message", "message", message, "is_own", isOwn)

	switch {
	case message.Tx != nil:
		rawTx := message.Tx.Data

		// Note: if an epoch transition is just about to happen we can be out of
		// the committee by the time we queue the transaction, but this is fine
		// as scheduling is aware of this.
		if es := n.commonNode.Group.GetEpochSnapshot(); !es.IsExecutorWorker() {
			n.logger.Debug("unable to handle transaction message, not execution worker",
				"current_epoch", es.GetEpochNumber(),
			)
			return true, nil
		}

		// Skip recently scheduled transactions.
		if n.lastScheduledCache != nil {
			if _, b := n.lastScheduledCache.Get(hash.NewFromBytes(rawTx)); b {
				n.logger.Debug("not scheduling duplicate transaction", "tx", rawTx)
				return true, nil
			}
		}
		// Queue transaction for checks.
		n.logger.Debug("queuing transaction for check",
			"tx", rawTx,
		)
		if err := n.checkTxQueue.Add(rawTx); err != nil {
			n.logger.Error("unable to queue transaction",
				"tx", rawTx,
				"err", err,
			)
			return true, err
		}
		n.checkTxCh.In() <- struct{}{}
		return true, nil

	case message.Proposal != nil:
		// Ignore own messages as those are handled separately.
		if isOwn {
			return true, nil
		}
		crash.Here(crashPointBatchReceiveAfter)

		proposal := message.Proposal

		epoch := n.commonNode.Group.GetEpochSnapshot()
		n.commonNode.CrossNode.Lock()
		round := n.commonNode.CurrentBlock.Header.Round
		n.commonNode.CrossNode.Unlock()

		// Before opening the signed dispatch message, verify that it was actually signed by the
		// current transaction scheduler.
		if err := epoch.VerifyTxnSchedulerSigner(proposal.SignedProposalHeader.Signature, round); err != nil {
			// Not signed by the current txn scheduler.
			return false, errMsgFromNonTxnSched
		}

		// Transaction scheduler checks out, open the signed dispatch message and add it to the
		// processing queue.
		var proposalHeader commitment.ProposalHeader
		if err := proposal.SignedProposalHeader.Open(n.commonNode.Runtime.ID(), &proposalHeader); err != nil {
			return false, p2pError.Permanent(err)
		}

		err := n.queueBatchBlocking(ctx, proposal, &proposalHeader)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	return false, nil
}

func (n *Node) queueBatchBlocking(
	ctx context.Context,
	proposal *commitment.Proposal,
	proposalHeader *commitment.ProposalHeader,
) error {
	rt, err := n.commonNode.Runtime.ActiveDescriptor(ctx)
	if err != nil {
		n.logger.Warn("failed to fetch active runtime descriptor",
			"err", err,
		)
		return p2pError.Permanent(err)
	}

	// Do a quick check on the batch size.
	if uint64(len(proposal.Batch)) > rt.TxnScheduler.MaxBatchSize {
		n.logger.Warn("received proposed batch contained too many transactions",
			"max_batch_size", rt.TxnScheduler.MaxBatchSize,
			"batch_size", len(proposal.Batch),
		)
		return errBatchTooLarge
	}

	batch := &unresolvedBatch{
		proposal:          proposal,
		proposalHeader:    proposalHeader,
		maxBatchSizeBytes: rt.TxnScheduler.MaxBatchSizeBytes,
	}

	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()
	return n.handleExternalBatchLocked(batch)
}

func (n *Node) bumpReselect() {
	select {
	case n.reselect <- struct{}{}:
	default:
		// If there's one already queued, we don't need to do anything.
	}
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
	// Restart our worker's select in case our state-specific channels have changed.
	n.bumpReselect()
}

// HandleEpochTransitionLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleEpochTransitionLocked(epoch *committee.EpochSnapshot) {
	n.schedulerMutex.RLock()
	defer n.schedulerMutex.RUnlock()
	if n.scheduler == nil {
		n.logger.Error("scheduling algorithm not available yet")
		return
	}

	switch {
	case epoch.IsExecutorWorker():
		if !n.prevEpochWorker {
			// Clear incoming queue and cache of any stale transactions in case
			// we were not part of the compute committee in previous epoch.
			n.clearQueuedTxs()
		}
		fallthrough
	case epoch.IsExecutorBackupWorker():
		n.transitionLocked(StateWaitingForBatch{})
	default:
		n.transitionLocked(StateNotReady{})
	}
	n.prevEpochWorker = epoch.IsExecutorWorker()
}

// HandleNewBlockEarlyLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(blk *block.Block) {
	crash.Here(crashPointRoothashReceiveAfter)
	// If we have seen a new block while a batch was processing, we need to
	// abort it no matter what as any processed state may be invalid.
	n.abortBatchLocked(errSeenNewerBlock)
	// Update our availability.
	n.nudgeAvailability(false)
}

// HandleNewBlockLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockLocked(blk *block.Block) {
	header := blk.Header

	// Cancel old round context, start a new one.
	if n.roundCancelCtx != nil {
		(n.roundCancelCtx)()
	}
	n.roundCtx, n.roundCancelCtx = context.WithCancel(n.ctx)

	// Perform actions based on current state.
	switch state := n.state.(type) {
	case StateWaitingForBlock:
		// Check if this was the block we were waiting for.
		currentHash := header.EncodedHash()
		if currentHash.Equal(&state.batch.proposalHeader.PreviousHash) {
			n.logger.Info("received block needed for batch processing")
			n.maybeStartProcessingBatchLocked(state.batch)
			break
		}

		// Check if the new block is for the same or newer round than the
		// one we are waiting for. In this case, we should abort as the
		// block will never be seen.
		curRound := header.Round
		waitRound := state.batch.proposalHeader.Round - 1
		if curRound >= waitRound {
			n.logger.Warn("seen newer block while waiting for block")
			n.transitionLocked(StateWaitingForBatch{})
			break
		}

		// Continue waiting for block.
		n.logger.Info("still waiting for block",
			"current_round", curRound,
			"wait_round", waitRound,
		)
	case StateWaitingForTxs:
		// Stop waiting for transactions and start a new round.
		n.logger.Warn("considering previous proposal invalid due to missing transactions")
		n.transitionLocked(StateWaitingForBatch{})
	case StateWaitingForEvent:
		// Block finalized without the need for a backup worker.
		n.logger.Info("considering the round finalized",
			"round", header.Round,
			"header_hash", header.EncodedHash(),
		)
		n.transitionLocked(StateWaitingForBatch{})
	case StateWaitingForFinalize:
		func() {
			defer n.transitionLocked(StateWaitingForBatch{})

			// A new block means the round has been finalized.
			n.logger.Info("considering the round finalized",
				"round", header.Round,
				"header_hash", header.EncodedHash(),
				"header_type", header.HeaderType,
			)
			if header.HeaderType != block.Normal {
				return
			}
			if !header.IORoot.Equal(&state.proposedIORoot) {
				n.logger.Error("proposed batch was not finalized",
					"header_io_root", header.IORoot,
					"proposed_io_root", state.proposedIORoot,
					"header_type", header.HeaderType,
					"batch_size", len(state.raw),
				)
				return
			}

			// Record time taken for successfully processing a batch.
			batchProcessingTime.With(n.getMetricLabels()).Observe(time.Since(state.batchStartTime).Seconds())

			n.logger.Debug("removing processed batch from queue",
				"batch_size", len(state.raw),
				"io_root", header.IORoot,
			)
			// Removed processed transactions from queue.
			if err := n.removeTxBatch(state.raw); err != nil {
				n.logger.Warn("failed removing processed batch from queue",
					"err", err,
					"batch_size", len(state.raw),
				)
			}
		}()
	}

	// Clear the potentially set "is proposing timeout" flag from the previous round.
	n.proposingTimeout = false

	if header.HeaderType != block.Normal {
		// If last round was not successful, make sure we re-query the round weight limits
		// before scheduling a batch as ExecuteTxResponse could have set invalid weights.
		n.schedulerMutex.Lock()
		n.limitsLastUpdate = header.Round - 1
		n.schedulerMutex.Unlock()
	}

	// Check if we are a proposer and if so try to immediately schedule a new batch.
	if n.commonNode.Group.GetEpochSnapshot().IsTransactionScheduler(blk.Header.Round) {
		n.logger.Info("we are a transaction scheduler",
			"round", blk.Header.Round,
		)

		n.checkTxCh.In() <- struct{}{}
	}
}

// checkTxBatch requests the runtime to check the validity of a transaction batch.
// Transactions that pass the check are queued for scheduling.
func (n *Node) checkTxBatch() {
	batch := n.checkTxQueue.GetBatch()
	if len(batch) == 0 {
		return
	}
	rt := n.GetHostedRuntime()
	if rt == nil {
		n.logger.Debug("CheckTx: hosted runtime not initialized")
		return
	}

	n.commonNode.CrossNode.Lock()
	currentBlock := n.commonNode.CurrentBlock
	currentConsensusBlock := n.commonNode.CurrentConsensusBlock
	currentEpoch := n.commonNode.Group.GetEpochSnapshot().GetEpochNumber()
	n.commonNode.CrossNode.Unlock()

	// Fetch the active descriptor so we can get the current message limits.
	rtDsc, err := n.commonNode.Runtime.ActiveDescriptor(n.ctx)
	if err != nil {
		n.logger.Error("failed to get active runtime descriptor",
			"err", err,
		)
		return
	}
	currentMaxMessages := rtDsc.Executor.MaxMessages

	// Check transaction batch.
	results, err := rt.CheckTx(n.ctx, currentBlock, currentConsensusBlock, currentEpoch, currentMaxMessages, batch)
	if err != nil {
		n.logger.Error("transaction batch check tx error", "err", err)
		return
	}

	txs := make([]*transaction.CheckedTransaction, 0, len(results))
	for i, res := range results {
		if !res.IsSuccess() {
			n.logger.Warn("check tx failed", "tx", batch[i], "result", res)
			continue
		}

		txs = append(txs, res.ToCheckedTransaction(batch[i]))
	}

	// Remove the checked transaction batch.
	n.checkTxQueue.RemoveBatch(batch)

	// Queue checked transactions for scheduling.
	n.queueTxBatch(txs)
}

// queueTxBatch queues a runtime transaction batch for scheduling.
func (n *Node) queueTxBatch(txs []*transaction.CheckedTransaction) {
	for _, tx := range txs {
		if err := n.scheduler.QueueTx(tx); err != nil {
			n.logger.Error("unable to schedule transaction", "tx", tx)
			continue
		}
		if n.lastScheduledCache != nil {
			if err := n.lastScheduledCache.Put(tx.Hash(), true); err != nil {
				// cache.Put can only error if capacity in bytes is used and the
				// inserted value is too large. This should never happen in here.
				n.logger.Error("cache put error",
					"err", err,
				)
			}
		}
	}

	incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.scheduler.UnscheduledSize()))

	// Check if we are waiting for new transactions.
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	state, ok := n.state.(StateWaitingForTxs)
	if !ok {
		return
	}

	for _, tx := range txs {
		delete(state.batch.missingTxs, tx.Hash())
	}
	if len(state.batch.missingTxs) == 0 {
		// We have all transactions, signal the node to start processing the batch.
		n.logger.Info("received all transactions needed for batch processing")
		n.startProcessingBatchLocked(state.batch)
	}
}

// removeTxBatch removes a batch from scheduling queue.
func (n *Node) removeTxBatch(batch transaction.RawBatch) error {
	hashes := make([]hash.Hash, len(batch))
	for i, b := range batch {
		hashes[i] = hash.NewFromBytes(b)
	}
	// XXX: remove batch can only happen after a batch was already scheduled, meaning
	// the scheduler already exists and there is no need for the scheduler mutex.
	if err := n.scheduler.RemoveTxBatch(hashes); err != nil {
		return err
	}

	incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.scheduler.UnscheduledSize()))

	return nil
}

// Assumes n.schedulerMutex lock is held.
func (n *Node) updateRoundWeightLimitsLocked(newBatchLimits map[transaction.Weight]uint64, round uint64) error {
	// Remove batch custom weight limits that don't exist anymore.
	for w := range n.roundWeightLimits {
		// Skip non custom runtime weights.
		if !w.IsCustom() {
			continue
		}

		if _, exists := newBatchLimits[w]; !exists {
			delete(n.roundWeightLimits, w)
		}
	}
	// Update batch weight limits.
	for w, l := range newBatchLimits {
		n.roundWeightLimits[w] = l
	}

	if err := n.scheduler.UpdateParameters(n.schedulerAlgorithm, n.roundWeightLimits); err != nil {
		return fmt.Errorf("updating scheduler parameters: %w", err)
	}
	n.limitsLastUpdate = round

	n.logger.Debug("updated round batch weight limits",
		"last_update_round", n.limitsLastUpdate,
		"weight_limits", n.roundWeightLimits,
	)

	return nil
}

func (n *Node) updateBatchWeightLimits(ctx context.Context, blk *block.Block, lb *consensus.LightBlock, epoch beacon.EpochTime) error {
	n.schedulerMutex.Lock()
	defer n.schedulerMutex.Unlock()

	if n.limitsLastUpdate != 0 && n.limitsLastUpdate >= blk.Header.Round {
		n.logger.Debug("skipping querying batch weight limits",
			"last_update_round", n.limitsLastUpdate,
			"round", blk.Header.Round,
			"weight_limits", n.roundWeightLimits,
		)
		// Already queried weights for this round.
		return nil
	}

	rt := n.GetHostedRuntime()
	if rt == nil {
		return fmt.Errorf("updating runtime weight limits while hosted runtime is not initialized")
	}

	// Query batch limits.
	batchLimits, err := rt.QueryBatchLimits(ctx, blk, lb, epoch)
	if err != nil {
		return fmt.Errorf("querying batch round limits: %w", err)
	}

	return n.updateRoundWeightLimitsLocked(batchLimits, blk.Header.Round)
}

func (n *Node) proposeTimeoutLocked(roundCtx context.Context) error {
	// Do not propose a timeout if we are already proposing it.
	// The flag will get cleared on the next round or if the propose timeout
	// tx fails.
	if n.proposingTimeout {
		return nil
	}

	if n.commonNode.CurrentBlock == nil {
		return fmt.Errorf("executor: propose timeout error, nil block")
	}
	rt, err := n.commonNode.Runtime.ActiveDescriptor(roundCtx)
	if err != nil {
		return err
	}
	proposerTimeout := rt.TxnScheduler.ProposerTimeout
	currentBlockHeight := n.commonNode.CurrentBlockHeight
	if n.commonNode.Height < currentBlockHeight+proposerTimeout {
		n.logger.Debug("executor: proposer timeout not reached yet",
			"height", n.commonNode.Height,
			"current_block_height", currentBlockHeight,
			"proposer_timeout", proposerTimeout,
		)
		return nil
	}

	n.logger.Debug("executor requesting proposer timeout",
		"height", n.commonNode.Height,
		"current_block_height", currentBlockHeight,
		"proposer_timeout", proposerTimeout,
	)
	n.proposingTimeout = true
	tx := roothash.NewRequestProposerTimeoutTx(0, nil, n.commonNode.Runtime.ID(), n.commonNode.CurrentBlock.Header.Round)
	go func(round uint64) {
		// Wait a bit before actually proposing a timeout, to give the current
		// scheduler some time to propose a batch in case it just received it.
		//
		// This prevents triggering a timeout when there is a long period
		// of no transactions, as without this artificial delay, the non
		// scheduler nodes would be faster in proposing a timeout than the
		// scheduler node proposing a batch.
		select {
		case <-time.After(proposeTimeoutDelay):
		case <-roundCtx.Done():
			n.logger.Info("not requesting proposer timeout, round context canceled")
			return
		}

		// Make sure we are still in the right state/round.
		n.commonNode.CrossNode.Lock()
		// Make sure we are still in the right state.
		var invalidState bool
		switch n.state.(type) {
		case StateWaitingForBatch, StateWaitingForTxs:
		default:
			invalidState = true
		}
		// Make sure we are still processing the right round.
		if round != n.commonNode.CurrentBlock.Header.Round {
			invalidState = true
		}
		if invalidState {
			n.logger.Info("not requesting proposer timeout",
				"height", n.commonNode.Height,
				"current_block_round", n.commonNode.CurrentBlock.Header.Round,
				"proposing_round", round,
				"state", n.state,
			)
			n.commonNode.CrossNode.Unlock()
			return
		}
		n.commonNode.CrossNode.Unlock()

		err := consensus.SignAndSubmitTx(roundCtx, n.commonNode.Consensus, n.commonNode.Identity.NodeSigner, tx)
		switch err {
		case nil:
			n.logger.Info("executor timeout request finalized",
				"height", n.commonNode.Height,
				"current_block_height", currentBlockHeight,
				"proposer_timeout", proposerTimeout,
			)
		default:
			n.logger.Error("failed to submit executor timeout request",
				"height", n.commonNode.Height,
				"current_block_height", currentBlockHeight,
				"err", err,
			)
			n.commonNode.CrossNode.Lock()
			n.proposingTimeout = false
			n.commonNode.CrossNode.Unlock()
		}
	}(n.commonNode.CurrentBlock.Header.Round)

	return nil
}

func (n *Node) getRtStateAndRoundResults(ctx context.Context, height int64) (*roothash.RuntimeState, *roothash.RoundResults, error) {
	state, err := n.commonNode.Consensus.RootHash().GetRuntimeState(ctx, &roothash.RuntimeRequest{
		RuntimeID: n.commonNode.Runtime.ID(),
		Height:    height,
	})
	if err != nil {
		n.logger.Error("failed to query runtime state",
			"err", err,
			"height", height,
		)
		return nil, nil, err
	}
	roundResults, err := n.commonNode.Runtime.History().GetRoundResults(ctx, state.LastNormalRound)
	switch err {
	case nil:
	case roothash.ErrNotFound:
		// It could be that we don't have the block because the node used state sync to skip past
		// the consensus block that contained the last normal round. We can still continue in case
		// the last normal round is actually the genesis round (as then we know that there were no
		// actual round results).
		if state.LastNormalRound == state.GenesisBlock.Header.Round {
			roundResults = &roothash.RoundResults{}
			break
		}

		fallthrough
	default:
		n.logger.Error("failed to query round last normal round results",
			"err", err,
			"height", height,
		)
		return nil, nil, err
	}

	return state, roundResults, nil
}

func (n *Node) handleScheduleBatch(force bool) {
	roundCtx, epoch, rtState, roundResults, blk, lb, err := func() (
		context.Context,
		*committee.EpochSnapshot,
		*roothash.RuntimeState,
		*roothash.RoundResults,
		*block.Block,
		*consensus.LightBlock,
		error,
	) {
		n.commonNode.CrossNode.Lock()
		defer n.commonNode.CrossNode.Unlock()
		roundCtx := n.roundCtx

		// Check if we are in a suitable state for scheduling a batch.
		switch n.state.(type) {
		case StateWaitingForBatch:
			// We are waiting for a batch.
		case StateWaitingForTxs:
			// We are waiting for transactions. Note that this means we are not a transaction
			// scheduler and so we won't actually be able to schedule anything. But we should still
			// propose a timeout if the transaction scheduler proposed something that nobody has.
		default:
			return roundCtx, nil, nil, nil, nil, nil, errIncorrectState
		}

		if n.commonNode.CurrentBlock == nil {
			return roundCtx, nil, nil, nil, nil, nil, errNoBlocks
		}
		epoch := n.commonNode.Group.GetEpochSnapshot()

		// If we are not an executor worker in this epoch, we don't need to do anything.
		if !epoch.IsExecutorWorker() {
			return roundCtx, nil, nil, nil, nil, nil, errNotExecutor
		}

		rtState, roundResults, err := n.getRtStateAndRoundResults(roundCtx, n.commonNode.CurrentBlockHeight)
		if err != nil {
			return roundCtx, nil, nil, nil, nil, nil, err
		}
		return roundCtx, epoch, rtState, roundResults, n.commonNode.CurrentBlock, n.commonNode.CurrentConsensusBlock, nil
	}()
	if err != nil {
		n.logger.Debug("not scheduling a batch",
			"err", err,
		)
		return
	}

	// Update per round scheduler parameters if needed.
	if err = n.updateBatchWeightLimits(roundCtx, blk, lb, epoch.GetEpochNumber()); err != nil {
		n.logger.Error("failed updating batch weight limits",
			"err", err,
		)
	}

	// Ask the scheduler to get a batch of transactions for us and see if we should be proposing
	// a new batch to other nodes.
	batch := n.scheduler.GetBatch(force)
	switch {
	case len(batch) > 0:
		// We have some transactions, schedule batch.
	case force && len(roundResults.Messages) > 0:
		// We have runtime message results (and batch timeout expired), schedule batch.
	case rtState.LastNormalRound == rtState.GenesisBlock.Header.Round:
		// This is the runtime genesis, schedule batch.
	case force && rtState.LastNormalHeight < epoch.GetGroupVersion():
		// No block in this epoch processed by runtime yet, schedule batch.
	default:
		// No need to schedule a batch.
		return
	}

	// If we are an executor and not a scheduler try proposing a timeout.
	if !epoch.IsTransactionScheduler(blk.Header.Round) {
		n.logger.Debug("proposing a timeout",
			"round", blk.Header.Round,
			"batch_size", len(batch),
			"round_results", roundResults,
		)

		err = func() error {
			n.commonNode.CrossNode.Lock()
			defer n.commonNode.CrossNode.Unlock()

			// Make sure we are still in the right state.
			switch n.state.(type) {
			case StateWaitingForBatch:
			case StateWaitingForTxs:
			default:
				return errIncorrectState
			}
			// Make sure we are still processing the right round.
			if blk.Header.Round != n.commonNode.CurrentBlock.Header.Round {
				return errIncorrectState
			}
			return n.proposeTimeoutLocked(roundCtx)
		}()
		switch err {
		case nil:
		case errIncorrectState:
			return
		default:
			n.logger.Error("error proposing a timeout",
				"err", err,
			)
		}

		// If we are not a transaction scheduler, we can't really schedule.
		n.logger.Debug("not scheduling a batch as we are not a transaction scheduler")
		return
	}

	n.logger.Debug("scheduling a batch",
		"batch_size", len(batch),
		"round_results", roundResults,
	)

	// Scheduler node starts batch processing.

	// Generate the initial I/O root containing only the inputs (outputs and
	// tags will be added later by the executor nodes).
	emptyRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round + 1,
		Type:      storage.RootTypeIO,
	}
	emptyRoot.Hash.Empty()

	ioTree := transaction.NewTree(nil, emptyRoot)
	defer ioTree.Close()

	rawBatch := make(transaction.RawBatch, len(batch))
	txHashes := make([]hash.Hash, len(batch))
	for idx, tx := range batch {
		if err = ioTree.AddTransaction(roundCtx, transaction.Transaction{Input: tx.Raw(), BatchOrder: uint32(idx)}, nil); err != nil {
			n.logger.Error("failed to create I/O tree",
				"err", err,
			)
			return
		}
		rawBatch[idx] = tx.Raw()
		txHashes[idx] = tx.Hash()
	}

	ioWriteLog, ioRoot, err := ioTree.Commit(roundCtx)
	if err != nil {
		n.logger.Error("failed to create I/O tree",
			"err", err,
		)
		return
	}

	// Commit I/O tree to local storage.

	err = n.storage.Apply(roundCtx, &storage.ApplyRequest{
		Namespace: blk.Header.Namespace,
		RootType:  storage.RootTypeIO,
		SrcRound:  blk.Header.Round + 1,
		SrcRoot:   emptyRoot.Hash,
		DstRound:  blk.Header.Round + 1,
		DstRoot:   ioRoot,
		WriteLog:  ioWriteLog,
	})
	if err != nil {
		n.logger.Error("failed to commit I/O tree to storage",
			"err", err,
		)
		return
	}

	// Create new proposal.
	proposalHeader := &commitment.ProposalHeader{
		Round:        blk.Header.Round + 1,
		PreviousHash: blk.Header.EncodedHash(),
		BatchHash:    ioRoot,
	}
	signedProposalHeader, err := proposalHeader.Sign(n.commonNode.Identity.NodeSigner, blk.Header.Namespace)
	if err != nil {
		n.logger.Error("failed to sign proposal header",
			"err", err,
		)
		return
	}

	proposal := &commitment.Proposal{
		SignedProposalHeader: *signedProposalHeader,
		Batch:                txHashes,
	}

	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	// Make sure we are still in the right state/round.
	if _, ok := n.state.(StateWaitingForBatch); !ok || blk.Header.Round != n.commonNode.CurrentBlock.Header.Round {
		n.logger.Error("new state or round since started the dispatch",
			"state", n.state,
			"expected_round", blk.Header.Round,
			"round", n.commonNode.CurrentBlock.Header.Round,
		)
		return
	}

	n.logger.Debug("dispatching a new batch proposal",
		"io_root", ioRoot,
		"batch_size", len(batch),
	)

	err = n.commonNode.Group.Publish(
		&p2p.Message{
			Proposal: proposal,
		},
	)
	if err != nil {
		n.logger.Error("failed to publish batch to committee",
			"err", err,
		)
		return
	}
	crash.Here(crashPointBatchPublishAfter)

	// Also process the batch locally.
	n.maybeStartProcessingBatchLocked(&unresolvedBatch{
		proposal:       proposal,
		proposalHeader: proposalHeader,
		batch:          rawBatch,
	})
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) maybeStartProcessingBatchLocked(batch *unresolvedBatch) {
	epoch := n.commonNode.Group.GetEpochSnapshot()

	switch {
	case epoch.IsExecutorWorker():
		// Worker, start processing immediately.
		n.startProcessingBatchLocked(batch)
	case epoch.IsExecutorBackupWorker():
		// Backup worker, wait for discrepancy event.
		state, ok := n.state.(StateWaitingForBatch)
		if ok && state.pendingEvent != nil {
			// We have already received a discrepancy event, start processing immediately.
			n.logger.Info("already received a discrepancy event, start processing batch")
			n.startProcessingBatchLocked(batch)
			return
		}

		n.transitionLocked(StateWaitingForEvent{batch: batch})
	default:
		// Currently not a member of an executor committee, log.
		n.logger.Debug("not an executor committee member, ignoring batch")
	}
}

func (n *Node) startLocalStorageReplication(
	ctx context.Context,
	blk *block.Block,
	ioRootHash hash.Hash,
	batch transaction.RawBatch,
) <-chan error {
	ch := make(chan error, 1)

	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round + 1,
		Type:      storage.RootTypeIO,
		Hash:      ioRootHash,
	}

	// If we have a local storage node, replicate batch locally so we will be able to Apply
	// locally later when proposing a batch. This also avoids needless replication for things
	// that we already have.
	replicateIO := make(chan error)
	go func() {
		defer close(replicateIO)

		// Check if the root is already present as in this case no replication is needed.
		if n.storage.NodeDB().HasRoot(ioRoot) {
			replicateIO <- nil
			return
		}

		n.logger.Debug("replicating I/O root locally",
			"io_root", ioRoot,
		)

		emptyRoot := ioRoot
		emptyRoot.Hash.Empty()

		ioTree := transaction.NewTree(nil, emptyRoot)
		defer ioTree.Close()

		for idx, tx := range batch {
			if err := ioTree.AddTransaction(ctx, transaction.Transaction{Input: tx, BatchOrder: uint32(idx)}, nil); err != nil {
				n.logger.Error("failed to create I/O tree",
					"err", err,
				)
				replicateIO <- err
				return
			}
		}

		ioWriteLog, ioRootHashCheck, err := ioTree.Commit(ctx)
		if err != nil {
			n.logger.Error("failed to create I/O tree",
				"err", err,
			)
			replicateIO <- err
			return
		}
		if !ioRootHashCheck.Equal(&ioRootHash) {
			n.logger.Error("inconsistent I/O root",
				"io_root_hash", ioRootHashCheck,
				"expected", ioRootHash,
			)
			replicateIO <- fmt.Errorf("inconsistent I/O root")
			return
		}

		err = n.storage.Apply(ctx, &storage.ApplyRequest{
			Namespace: ioRoot.Namespace,
			RootType:  ioRoot.Type,
			SrcRound:  ioRoot.Version,
			SrcRoot:   emptyRoot.Hash,
			DstRound:  ioRoot.Version,
			DstRoot:   ioRoot.Hash,
			WriteLog:  ioWriteLog,
		})
		if err != nil {
			n.logger.Error("failed to apply I/O tree locally",
				"err", err,
			)
			replicateIO <- err
			return
		}

		replicateIO <- nil
	}()

	// Wait for replication to complete.
	go func() {
		defer close(ch)

		var combinedErr error
		select {
		case <-ctx.Done():
			combinedErr = ctx.Err()
		case err := <-replicateIO:
			if err != nil {
				combinedErr = fmt.Errorf("failed to replicate I/O root: %w", err)
			}
		}

		n.logger.Debug("local storage replication done",
			"io_root", ioRoot,
		)

		ch <- combinedErr
	}()

	return ch
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) startProcessingBatchLocked(batch *unresolvedBatch) {
	if n.commonNode.CurrentBlock == nil {
		panic("attempted to start processing batch with a nil block")
	}

	// Try to resolve the batch first.
	n.logger.Debug("attempting to resolve batch", "batch", batch.String())

	// TODO: Add metrics for how long it takes to receive the complete batch.
	resolvedBatch, err := batch.resolve(n.scheduler)
	if err != nil {
		n.logger.Error("refusing to process bad batch", "err", err)
		// TODO: We should indicate failure.
		return
	}
	if resolvedBatch == nil {
		// Some transactions are missing so we cannot start processing the batch just yet.
		// Transition into StateWaitingForTxs and request transactions from peers.
		n.logger.Debug("some transactions are missing", "num_missing", len(batch.missingTxs))
		// TODO: Actually request transactions from peers.
		n.transitionLocked(StateWaitingForTxs{batch})
		return
	}

	n.logger.Debug("processing batch",
		"batch_size", len(resolvedBatch),
	)

	// Create batch processing context and channel for receiving the response.
	ctx, cancel := context.WithCancel(n.roundCtx)
	done := make(chan *processedBatch, 1)

	batchStartTime := time.Now()
	n.transitionLocked(StateProcessingBatch{batch, batchStartTime, cancel, done})

	rt := n.GetHostedRuntime()
	if rt == nil {
		// This should not happen as we only register to be an executor worker
		// once the hosted runtime is ready.
		n.logger.Error("received a batch while hosted runtime is not yet initialized")
		n.abortBatchLocked(errRuntimeAborted)
		return
	}

	// Request the worker host to process a batch. This is done in a separate
	// goroutine so that the committee node can continue processing blocks.
	blk := n.commonNode.CurrentBlock
	consensusBlk := n.commonNode.CurrentConsensusBlock
	height := n.commonNode.CurrentBlockHeight
	epoch := n.commonNode.Group.GetEpochSnapshot()

	go func() {
		defer close(done)

		state, roundResults, err := n.getRtStateAndRoundResults(ctx, height)
		if err != nil {
			n.logger.Error("failed to query runtime state and last round results",
				"err", err,
				"height", height,
				"round", blk.Header.Round,
			)
			return
		}

		// Optionally start local storage replication in parallel to batch dispatch.
		replicateCh := n.startLocalStorageReplication(ctx, blk, batch.hash(), resolvedBatch)

		rq := &protocol.Body{
			RuntimeExecuteTxBatchRequest: &protocol.RuntimeExecuteTxBatchRequest{
				ConsensusBlock: *consensusBlk,
				RoundResults:   roundResults,
				IORoot:         batch.hash(),
				Inputs:         resolvedBatch,
				Block:          *blk,
				Epoch:          epoch.GetEpochNumber(),
				MaxMessages:    state.Runtime.Executor.MaxMessages,
			},
		}
		batchSize.With(n.getMetricLabels()).Observe(float64(len(resolvedBatch)))

		rtStartTime := time.Now()
		defer func() {
			batchRuntimeProcessingTime.With(n.getMetricLabels()).Observe(time.Since(rtStartTime).Seconds())
		}()

		rsp, err := rt.Call(ctx, rq)
		switch {
		case err == nil:
		case errors.Is(err, context.Canceled):
			// Context was canceled while the runtime was processing a request.
			n.logger.Error("batch processing aborted by context, restarting runtime")

			// Abort the runtime, so we can start processing the next batch.
			abortCtx, cancel := context.WithTimeout(n.ctx, abortTimeout)
			defer cancel()

			if err = rt.Abort(abortCtx, false); err != nil {
				n.logger.Error("failed to abort the runtime",
					"err", err,
				)
			}
			return
		default:
			n.logger.Error("error while sending batch processing request to runtime",
				"err", err,
			)
			return
		}
		crash.Here(crashPointBatchProcessStartAfter)

		if rsp.RuntimeExecuteTxBatchResponse == nil {
			n.logger.Error("malformed response from runtime",
				"response", rsp,
			)
			return
		}

		// Update round batch weight limits.
		n.schedulerMutex.Lock()
		if err = n.updateRoundWeightLimitsLocked(rsp.RuntimeExecuteTxBatchResponse.BatchWeightLimits, blk.Header.Round+1); err != nil {
			n.logger.Error("failed updating batch weight limits",
				"err", err,
			)
		}
		n.schedulerMutex.Unlock()

		// Wait for replication to complete before proposing a batch to ensure that we can cleanly
		// apply any updates.
		select {
		case <-ctx.Done():
			return
		case err = <-replicateCh:
			if err != nil {
				n.logger.Error("local storage replication failed",
					"err", err,
				)
				return
			}
		}

		// Submit response to the executor worker.
		done <- &processedBatch{
			computed: &rsp.RuntimeExecuteTxBatchResponse.Batch,
			raw:      resolvedBatch,
		}
	}()
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) abortBatchLocked(reason error) {
	state, ok := n.state.(StateProcessingBatch)
	if !ok {
		// We can only abort if a batch is being processed.
		return
	}

	n.logger.Warn("aborting batch",
		"reason", reason,
	)

	// Cancel the batch processing context and wait for it to finish.
	state.cancel()

	crash.Here(crashPointBatchAbortAfter)

	abortedBatchCount.With(n.getMetricLabels()).Inc()
	// After the batch has been aborted, we must wait for the round to be
	// finalized.
	n.transitionLocked(StateWaitingForFinalize{
		batchStartTime: state.batchStartTime,
	})
}

func (n *Node) proposeBatch(
	roundCtx context.Context,
	lastHeader *block.Header,
	unresolved *unresolvedBatch,
	processed *processedBatch,
) {
	crash.Here(crashPointBatchProposeBefore)

	batch := processed.computed
	epoch := n.commonNode.Group.GetEpochSnapshot()

	n.logger.Debug("proposing batch",
		"batch_size", len(processed.raw),
	)

	// Generate proposed compute results.
	rakSig := batch.RakSig
	proposedResults := &commitment.ComputeBody{
		Header: batch.Header,
		RakSig: &rakSig,
	}
	// If we are the transaction scheduler also include all the emitted messages.
	if epoch.IsTransactionScheduler(lastHeader.Round) {
		proposedResults.Messages = batch.Messages
	}

	// Commit I/O and state write logs to storage.
	storageErr := func() error {
		start := time.Now()
		defer storageCommitLatency.With(n.getMetricLabels()).Observe(time.Since(start).Seconds())

		ctx, cancel := context.WithCancel(roundCtx)
		defer cancel()

		// Store final I/O root.
		err := n.storage.Apply(ctx, &storage.ApplyRequest{
			Namespace: lastHeader.Namespace,
			RootType:  storage.RootTypeIO,
			SrcRound:  lastHeader.Round + 1,
			SrcRoot:   unresolved.hash(),
			DstRound:  lastHeader.Round + 1,
			DstRoot:   *batch.Header.IORoot,
			WriteLog:  batch.IOWriteLog,
		})
		if err != nil {
			return err
		}
		// Update state root.
		err = n.storage.Apply(ctx, &storage.ApplyRequest{
			Namespace: lastHeader.Namespace,
			RootType:  storage.RootTypeState,
			SrcRound:  lastHeader.Round,
			SrcRoot:   lastHeader.StateRoot,
			DstRound:  lastHeader.Round + 1,
			DstRoot:   *batch.Header.StateRoot,
			WriteLog:  batch.StateWriteLog,
		})
		if err != nil {
			return err
		}

		return nil
	}()
	if storageErr != nil {
		n.logger.Error("storage failure, submitting failure indicating commitment",
			"err", storageErr,
		)
		proposedResults.SetFailure(commitment.FailureUnknown)
	}

	// Submit commitment.
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	// Make sure we are still in the right state/round.
	state, ok := n.state.(StateProcessingBatch)
	if !ok || lastHeader.Round != n.commonNode.CurrentBlock.Header.Round {
		n.logger.Error("new state or round since started proposing batch",
			"state", state,
			"round", n.commonNode.CurrentBlock.Header.Round,
			"expected_round", lastHeader.Round,
		)
		return
	}

	if err := n.signAndSubmitCommitment(roundCtx, proposedResults); err != nil {
		n.logger.Error("failed to sign and submit the commitment",
			"commit", proposedResults,
			"err", err,
		)
		n.abortBatchLocked(err)
		return
	}

	switch storageErr {
	case nil:
		n.transitionLocked(StateWaitingForFinalize{
			batchStartTime: state.batchStartTime,
			raw:            processed.raw,
			proposedIORoot: *proposedResults.Header.IORoot,
		})
	default:
		n.abortBatchLocked(storageErr)
	}

	crash.Here(crashPointBatchProposeAfter)
}

func (n *Node) signAndSubmitCommitment(roundCtx context.Context, body *commitment.ComputeBody) error {
	commit, err := commitment.SignExecutorCommitment(n.commonNode.Identity.NodeSigner, n.commonNode.Runtime.ID(), body)
	if err != nil {
		n.logger.Error("failed to sign commitment",
			"commit", body,
			"err", err,
		)
		return err
	}

	tx := roothash.NewExecutorCommitTx(0, nil, n.commonNode.Runtime.ID(), []commitment.ExecutorCommitment{*commit})
	go func() {
		commitErr := consensus.SignAndSubmitTx(roundCtx, n.commonNode.Consensus, n.commonNode.Identity.NodeSigner, tx)
		switch commitErr {
		case nil:
			n.logger.Info("executor commit finalized")
		default:
			n.logger.Error("failed to submit executor commit",
				"commit", body,
				"err", commitErr,
			)
		}
	}()

	return nil
}

// HandleNewEventLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewEventLocked(ev *roothash.Event) {
	switch {
	case ev.ExecutionDiscrepancyDetected != nil:
		n.logger.Warn("execution discrepancy detected")

		crash.Here(crashPointDiscrepancyDetectedAfter)

		discrepancyDetectedCount.With(n.getMetricLabels()).Inc()

		// If the node is not a backup worker in this epoch, no need to do anything. Also if the
		// node is an executor worker in this epoch, then it has already processed and submitted
		// a commitment, so no need to do anything.
		epoch := n.commonNode.Group.GetEpochSnapshot()
		if !epoch.IsExecutorBackupWorker() || epoch.IsExecutorWorker() {
			return
		}

		var state StateWaitingForEvent
		switch s := n.state.(type) {
		case StateWaitingForBatch:
			// Discrepancy detected event received before the batch. We need to
			// record the received event and keep waiting for the batch.
			s.pendingEvent = ev.ExecutionDiscrepancyDetected
			n.transitionLocked(s)
			return
		case StateWaitingForEvent:
			state = s
		default:
			n.logger.Warn("ignoring received discrepancy event in incorrect state",
				"state", s,
			)
			return
		}

		// Backup worker, start processing a batch.
		n.logger.Info("backup worker activating and processing batch")
		n.startProcessingBatchLocked(state.batch)
	}
}

// HandleNodeUpdateLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNodeUpdateLocked(update *nodes.NodeUpdate, snapshot *committee.EpochSnapshot) {
	// Nothing to do here.
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) handleExternalBatchLocked(batch *unresolvedBatch) error {
	// If we are not waiting for a batch, don't do anything.
	if _, ok := n.state.(StateWaitingForBatch); !ok {
		return errIncorrectState
	}

	epoch := n.commonNode.Group.GetEpochSnapshot()

	// We can only receive external batches if we are an executor member.
	if !epoch.IsExecutorMember() {
		n.logger.Error("got external batch while in incorrect role")
		return errIncorrectRole
	}

	// Check if we have the correct block -- in this case, start processing the batch.
	currentHash := n.commonNode.CurrentBlock.Header.EncodedHash()
	if currentHash.Equal(&batch.proposalHeader.PreviousHash) {
		n.maybeStartProcessingBatchLocked(batch)
		return nil
	}

	// Check if the current block is older than what is expected we base our batch
	// on. In case it is equal or newer, but different, discard the batch.
	curRound := n.commonNode.CurrentBlock.Header.Round
	waitRound := batch.proposalHeader.Round - 1
	if curRound >= waitRound {
		n.logger.Warn("got external batch based on incompatible header",
			"previous_hash", batch.proposalHeader.PreviousHash,
			"round", batch.proposalHeader.Round,
		)
		return errIncompatibleHeader
	}

	// Wait for the correct block to arrive.
	n.transitionLocked(StateWaitingForBlock{
		batch: batch,
	})

	return nil
}

// nudeAvailability checks whether the executor worker should declare itself available.
func (n *Node) nudgeAvailability(force bool) {
	// Check availability of the last round which is needed for round processing.
	_, _, err := n.getRtStateAndRoundResults(n.ctx, consensus.HeightLatest)
	lastRoundAvailable := (err == nil)

	switch {
	case n.runtimeReady && lastRoundAvailable:
		// Executor is ready to process requests.
		if n.roleProvider.IsAvailable() && !force {
			break
		}

		n.roleProvider.SetAvailable(func(nd *node.Node) error {
			rt := nd.AddOrUpdateRuntime(n.commonNode.Runtime.ID())
			rt.Version = n.runtimeVersion
			rt.Capabilities.TEE = n.runtimeCapabilityTEE
			return nil
		})
	default:
		// Executor is not ready to process requests.
		if !n.roleProvider.IsAvailable() && !force {
			break
		}

		n.roleProvider.SetUnavailable()
	}
}

func (n *Node) handleRuntimeHostEvent(ev *host.Event) {
	switch {
	case ev.Started != nil:
		// We are now able to service requests for this runtime.
		n.runtimeReady = true
		n.runtimeVersion = ev.Started.Version
		n.runtimeCapabilityTEE = ev.Started.CapabilityTEE
	case ev.Updated != nil:
		// Update runtime capabilities.
		n.runtimeReady = true
		n.runtimeCapabilityTEE = ev.Updated.CapabilityTEE
	case ev.FailedToStart != nil, ev.Stopped != nil:
		// Runtime failed to start or was stopped -- we can no longer service requests.
		n.runtimeReady = false
	default:
		// Unknown event.
		n.logger.Warn("unknown worker event",
			"ev", ev,
		)
	}

	n.nudgeAvailability(true)
}

func (n *Node) handleProcessedBatch(batch *processedBatch, processingCh chan *processedBatch) {
	n.commonNode.CrossNode.Lock()

	// To avoid stale events, check if the stored state is still valid.
	// XXX: processingCh not changing ensures we are in the same state and not
	// in a "new" processing batch state. This also ensures that the round did
	// not change.
	state, ok := n.state.(StateProcessingBatch)
	if !ok || state.done != processingCh {
		n.commonNode.CrossNode.Unlock()
		return
	}
	roundCtx := n.roundCtx
	lastHeader := n.commonNode.CurrentBlock.Header

	// Successfully processed a batch.
	if batch != nil && batch.computed != nil {
		stateBatch := state.batch
		n.commonNode.CrossNode.Unlock()
		n.logger.Info("worker has finished processing a batch")
		n.proposeBatch(roundCtx, &lastHeader, stateBatch, batch)
		return
	}

	defer n.commonNode.CrossNode.Unlock()

	// Unsuccessful batch processing.
	n.logger.Warn("worker has aborted batch processing")
	commit := &commitment.ComputeBody{
		Header: commitment.ComputeResultsHeader{
			Round:        lastHeader.Round + 1,
			PreviousHash: lastHeader.EncodedHash(),
		},
	}
	commit.SetFailure(commitment.FailureUnknown)

	n.logger.Debug("submitting failure indicating commitment",
		"commitment", commit,
	)
	if err := n.signAndSubmitCommitment(roundCtx, commit); err != nil {
		n.logger.Error("failed to sign and submit the commitment",
			"commit", commit,
			"err", err,
		)
	}

	n.abortBatchLocked(errRuntimeAborted)
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

	// Provision the hosted runtime.
	hrt, hrtNotifier, err := n.ProvisionHostedRuntime(n.ctx)
	if err != nil {
		n.logger.Error("failed to provision hosted runtime",
			"err", err,
		)
		return
	}

	hrtEventCh, hrtSub, err := hrt.WatchEvents(n.ctx)
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

	// Initialize transaction scheduling algorithm with latest registry desctiptor.
	// Note: in case the runtime is already running, the correct active descriptor
	// is the version at the last epoch transition.
	// This case will be handled by the first tick from the descriptor updates
	// channel bellow, which will update the parameters.
	runtime, err := n.commonNode.Runtime.ActiveDescriptor(n.ctx)
	if err != nil {
		n.logger.Error("failed to fetch runtime registry descriptor",
			"err", err,
		)
		return
	}

	n.schedulerMutex.Lock()
	n.schedulerAlgorithm = runtime.TxnScheduler.Algorithm
	scheduler, err := scheduling.New(
		n.scheduleMaxTxPoolSize,
		n.schedulerAlgorithm,
		n.roundWeightLimits,
	)
	if err != nil {
		n.logger.Error("failed to create new transaction scheduler algorithm",
			"err", err,
		)
		n.schedulerMutex.Unlock()
		return
	}
	n.scheduler = scheduler
	n.schedulerMutex.Unlock()

	// Check incoming queue every FlushTimeout.
	txnScheduleTicker := time.NewTicker(runtime.TxnScheduler.BatchFlushTimeout)
	defer txnScheduleTicker.Stop()

	// Watch runtime descriptor updates.
	rtCh, rtSub, err := n.commonNode.Runtime.WatchActiveDescriptor()
	if err != nil {
		n.logger.Error("failed to watch runtimes",
			"err", err,
		)
		return
	}
	defer rtSub.Close()

	// We are initialized.
	close(n.initCh)

	for {
		// Check if we are currently processing a batch. In this case, we also
		// need to select over the result channel.
		var processingDoneCh chan *processedBatch

		func() {
			n.commonNode.CrossNode.Lock()
			defer n.commonNode.CrossNode.Unlock()

			if stateProcessing, ok := n.state.(StateProcessingBatch); ok {
				processingDoneCh = stateProcessing.done
			}
		}()

		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case ev := <-hrtEventCh:
			n.handleRuntimeHostEvent(ev)
		case batch := <-processingDoneCh:
			// Batch processing has finished.
			n.handleProcessedBatch(batch, processingDoneCh)
		case runtime := <-rtCh:
			// XXX: Once there is more than one scheduling algorithm available
			// this might need to recreate the scheduler and reinsert
			// the transactions.
			// At that point also update the schedulerMutex usage across the
			// code, as it will be no longer be true that the scheduler
			// variable never gets updated.

			// Update per round weight limits.
			n.schedulerMutex.Lock()
			n.roundWeightLimits[transaction.WeightConsensusMessages] = uint64(runtime.Executor.MaxMessages)
			n.roundWeightLimits[transaction.WeightSizeBytes] = runtime.TxnScheduler.MaxBatchSizeBytes
			n.roundWeightLimits[transaction.WeightCount] = runtime.TxnScheduler.MaxBatchSize
			n.schedulerAlgorithm = runtime.TxnScheduler.Algorithm
			if err = n.scheduler.UpdateParameters(n.schedulerAlgorithm, n.roundWeightLimits); err != nil {
				n.logger.Error("error updating scheduler parameters",
					"err", err,
				)
				n.schedulerMutex.Unlock()
				return
			}
			n.schedulerMutex.Unlock()

			// Update batch flush timeout ticker.
			txnScheduleTicker.Reset(runtime.TxnScheduler.BatchFlushTimeout)
		case <-txnScheduleTicker.C:
			// Force scheduling a batch if possible.
			n.handleScheduleBatch(true)
		case <-n.checkTxCh.Out():
			// Check any queued transactions and attempt regular scheduling.
			n.checkTxBatch()
			n.handleScheduleBatch(false)
		case <-n.reselect:
			// Recalculate select set.
		}
	}
}

// NewNode initializes a new executor node.
func NewNode(
	commonNode *committee.Node,
	commonCfg commonWorker.Config,
	roleProvider registration.RoleProvider,
	scheduleMaxTxPoolSize uint64,
	lastScheduledCacheSize uint64,
	checkTxMaxBatchSize uint64,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	// Prepare the runtime host node helpers.
	rhn, err := runtimeRegistry.NewRuntimeHostNode(commonNode)
	if err != nil {
		return nil, err
	}

	var cache *lru.Cache
	if lastScheduledCacheSize > 0 {
		cache, err = lru.New(lru.Capacity(lastScheduledCacheSize, false))
		if err != nil {
			return nil, fmt.Errorf("error creating cache: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		RuntimeHostNode:       rhn,
		commonNode:            commonNode,
		commonCfg:             commonCfg,
		roleProvider:          roleProvider,
		scheduleMaxTxPoolSize: scheduleMaxTxPoolSize,
		lastScheduledCache:    cache,
		checkTxQueue:          orderedmap.New(scheduleMaxTxPoolSize, checkTxMaxBatchSize),
		roundWeightLimits:     make(map[transaction.Weight]uint64),
		checkTxCh:             channels.NewRingChannel(1),
		ctx:                   ctx,
		cancelCtx:             cancel,
		stopCh:                make(chan struct{}),
		quitCh:                make(chan struct{}),
		initCh:                make(chan struct{}),
		state:                 StateNotReady{},
		stateTransitions:      pubsub.NewBroker(false),
		reselect:              make(chan struct{}, 1),
		logger:                logging.GetLogger("worker/executor/committee").With("runtime_id", commonNode.Runtime.ID()),
	}

	// Register prune handler.
	commonNode.Runtime.History().Pruner().RegisterHandler(&pruneHandler{commonNode: commonNode})

	return n, nil
}
