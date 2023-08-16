package committee

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	p2pError "github.com/oasisprotocol/oasis-core/go/p2p/error"
	p2pProtocol "github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/txsync"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

var (
	errSeenNewerBlock     = fmt.Errorf("executor: seen newer block")
	errRuntimeAborted     = fmt.Errorf("executor: runtime aborted batch processing")
	errBatchTooLarge      = p2pError.Permanent(fmt.Errorf("executor: batch too large"))
	errMsgFromNonTxnSched = fmt.Errorf("executor: received txn scheduler dispatch msg from non-txn scheduler")

	// proposeTimeoutDelay is the duration to wait before submitting the propose timeout request.
	proposeTimeoutDelay = 2 * time.Second
	// abortTimeout is the duration to wait for the runtime to abort.
	abortTimeout = 5 * time.Second
	// getInfoTimeout is the maximum time the runtime can spend replying to GetInfo.
	getInfoTimeout = 5 * time.Second
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
	nodeCollectors = []prometheus.Collector{
		discrepancyDetectedCount,
		abortedBatchCount,
		storageCommitLatency,
		batchProcessingTime,
		batchRuntimeProcessingTime,
		batchSize,
	}

	metricsOnce sync.Once
)

// Node is a committee node.
type Node struct { // nolint: maligned
	runtimeReady         bool
	runtimeVersion       version.Version
	runtimeTrustSynced   bool
	runtimeTrustSyncCncl context.CancelFunc

	// Guarded by .commonNode.CrossNode.
	proposingTimeout bool
	missingTxsCancel context.CancelFunc
	pendingProposals *pendingProposals

	commonNode   *committee.Node
	commonCfg    commonWorker.Config
	roleProvider registration.RoleProvider

	committeeTopic string

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

	commitPool commitment.Pool

	storage storage.LocalBackend
	txSync  txsync.Client

	stateTransitions *pubsub.Broker
	// Bump this when we need to change what the worker selects over.
	reselect chan struct{}

	logger *logging.Logger
}

// Name returns the service name.
func (n *Node) Name() string {
	return "executor committee node"
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

func (n *Node) processProposal(ctx context.Context, proposal *commitment.Proposal) error {
	rt, err := n.commonNode.Runtime.ActiveDescriptor(ctx)
	if err != nil {
		n.logger.Warn("failed to fetch active runtime descriptor",
			"err", err,
		)
		// Do not forward the proposal further as we are unable to validate it.
		return p2pError.Permanent(err)
	}

	// Do a quick check on the batch size.
	if uint64(len(proposal.Batch)) > rt.TxnScheduler.MaxBatchSize {
		n.logger.Warn("received proposed batch contained too many transactions",
			"max_batch_size", rt.TxnScheduler.MaxBatchSize,
			"batch_size", len(proposal.Batch),
		)
		// Do not forward the proposal further as it seems invalid.
		return errBatchTooLarge
	}

	batch := &unresolvedBatch{
		proposal:          proposal,
		maxBatchSizeBytes: rt.TxnScheduler.MaxBatchSizeBytes,
	}

	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()
	return n.handleProposalLocked(batch)
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
	switch {
	case epoch.IsExecutorWorker(), epoch.IsExecutorBackupWorker():
		n.transitionLocked(StateWaitingForBatch{})
	default:
		n.transitionLocked(StateNotReady{})
	}
}

// HandleNewBlockEarlyLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(bi *runtime.BlockInfo) {
	crash.Here(crashPointRoothashReceiveAfter)

	// If we have seen a new block while a batch was processing, we need to
	// abort it no matter what as any processed state may be invalid.
	n.abortBatchLocked(errSeenNewerBlock)
	// Update our availability.
	n.nudgeAvailabilityLocked(false)
}

// HandleNewBlockLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockLocked(bi *runtime.BlockInfo) {
	header := bi.RuntimeBlock.Header

	// Cancel old round context, start a new one.
	if n.roundCancelCtx != nil {
		(n.roundCancelCtx)()
	}
	n.roundCtx, n.roundCancelCtx = context.WithCancel(n.ctx)

	clearProposalQueue := true

	// Perform actions based on current state.
	switch state := n.state.(type) {
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
					"batch_size", len(state.txHashes),
				)
				return
			}

			// Record time taken for successfully processing a batch.
			batchProcessingTime.With(n.getMetricLabels()).Observe(time.Since(state.batchStartTime).Seconds())

			n.logger.Debug("removing processed batch from queue",
				"batch_size", len(state.txHashes),
				"io_root", header.IORoot,
			)
			// Remove processed transactions from queue.
			n.commonNode.TxPool.HandleTxsUsed(state.txHashes)
		}()
	}

	// Clear proposal queue.
	if clearProposalQueue {
		n.commonNode.TxPool.ClearProposedBatch()
	}

	// Clear the potentially set "is proposing timeout" flag from the previous round.
	n.proposingTimeout = false

	// Check if we are a proposer and if so try to immediately schedule a new batch.
	if n.commonNode.Group.GetEpochSnapshot().IsTransactionScheduler(header.Round) {
		n.logger.Info("we are a transaction scheduler",
			"round", header.Round,
		)

		n.commonNode.TxPool.WakeupScheduler()
	}

	// Check if we have any pending proposals and attempt to handle them.
	n.handlePendingProposalsLocked()
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
	rq := &roothash.RuntimeRequest{
		RuntimeID: n.commonNode.Runtime.ID(),
		Height:    height,
	}
	state, err := n.commonNode.Consensus.RootHash().GetRuntimeState(ctx, rq)
	if err != nil {
		n.logger.Error("failed to query runtime state",
			"err", err,
			"height", height,
		)
		return nil, nil, err
	}
	roundResults, err := n.commonNode.Consensus.RootHash().GetLastRoundResults(ctx, rq)
	if err != nil {
		n.logger.Error("failed to query round last normal round results",
			"err", err,
			"height", height,
		)
		return nil, nil, err
	}

	return state, roundResults, nil
}

func (n *Node) handleScheduleBatch(force bool) { // nolint: gocyclo
	n.commonNode.CrossNode.Lock()
	defer n.commonNode.CrossNode.Unlock()

	// Check if we are in a suitable state for scheduling a batch.
	switch n.state.(type) {
	case StateWaitingForBatch:
		// We are waiting for a batch.
	case StateWaitingForTxs:
		// We are waiting for transactions. Note that this means we are not a transaction
		// scheduler and so we won't actually be able to schedule anything. But we should still
		// propose a timeout if the transaction scheduler proposed something that nobody has.
	default:
		n.logger.Debug("not scheduling a batch, incorrect state", "state", n.state)
		return
	}
	if n.commonNode.CurrentBlock == nil {
		n.logger.Debug("not scheduling a batch, no blocks")
		return
	}

	epoch := n.commonNode.Group.GetEpochSnapshot()
	// If we are not an executor worker in this epoch, we don't need to do anything.
	if !epoch.IsExecutorWorker() {
		n.logger.Debug("not scheduling a batch, not an executor")
		return
	}

	// If the next block will be an epoch transition block, do not propose anything as it will be
	// reverted anyway (since the committee will change).
	epochState, err := n.commonNode.Consensus.Beacon().GetFutureEpoch(n.roundCtx, n.commonNode.CurrentBlockHeight)
	if err != nil {
		n.logger.Error("failed to fetch future epoch state",
			"err", err,
		)
		return
	}
	if epochState != nil && epochState.Height == n.commonNode.CurrentBlockHeight+1 {
		n.logger.Debug("not scheduling a batch, next consensus block is an epoch transition")
		return
	}

	rtState, roundResults, err := n.getRtStateAndRoundResults(n.roundCtx, n.commonNode.CurrentBlockHeight)
	if err != nil {
		n.logger.Debug("not scheduling a batch",
			"err", err,
		)
		return
	}

	// Fetch incoming message queue metadata to see if there's any queued messages.
	inMsgMeta, err := n.commonNode.Consensus.RootHash().GetIncomingMessageQueueMeta(n.roundCtx, &roothash.RuntimeRequest{
		RuntimeID: n.commonNode.Runtime.ID(),
		// We make the check at the latest height even though we will later only look at the last
		// height. This will make sure that any messages eventually get processed even if there are
		// no other runtime transactions being sent. In the worst case this will result in an empty
		// block being generated.
		Height: consensus.HeightLatest,
	})
	if err != nil {
		n.logger.Error("failed to fetch incoming runtime message queue metadata",
			"err", err,
		)
		return
	}

	// Check what the runtime supports.
	rt := n.commonNode.GetHostedRuntime()
	if rt == nil {
		n.logger.Debug("not scheduling a batch, the runtime is not yet ready")
		return
	}
	rtInfo, err := rt.GetInfo(n.roundCtx)
	if err != nil {
		n.logger.Warn("not scheduling a batch, the runtime is broken",
			"err", err,
		)
		return
	}
	if !rtInfo.Features.HasScheduleControl() {
		n.logger.Error("runtime does not support schedule control")
		return
	}

	// Ask the transaction pool to get a batch of transactions for us and see if we should be
	// proposing a new batch to other nodes.
	batch := n.commonNode.TxPool.GetSchedulingSuggestion(rtInfo.Features.ScheduleControl.InitialBatchSize)
	defer n.commonNode.TxPool.FinishScheduling()
	switch {
	case len(batch) > 0:
		// We have some transactions, schedule batch.
	case force && len(roundResults.Messages) > 0:
		// We have runtime message results (and batch timeout expired), schedule batch.
	case force && inMsgMeta.Size > 0:
		// We have queued incoming runtime messages (and batch timeout expired), schedule batch.
	case rtState.LastNormalRound == rtState.GenesisBlock.Header.Round:
		// This is the runtime genesis, schedule batch.
	case force && rtState.LastNormalHeight < epoch.GetEpochHeight():
		// No block in this epoch processed by runtime yet, schedule batch.
	default:
		// No need to schedule a batch.
		return
	}

	// If we are an executor and not a scheduler try proposing a timeout.
	if !epoch.IsTransactionScheduler(n.commonNode.CurrentBlock.Header.Round) {
		n.logger.Debug("considering to propose a timeout",
			"round", n.commonNode.CurrentBlock.Header.Round,
			"batch_size", len(batch),
			"round_results", roundResults,
		)

		if err := n.proposeTimeoutLocked(n.roundCtx); err != nil {
			n.logger.Error("error proposing a timeout",
				"err", err,
			)
		}

		// If we are not a transaction scheduler, we can't really schedule.
		n.logger.Debug("not scheduling a batch, not a transaction scheduler")
		return
	}

	n.startRuntimeBatchSchedulingLocked(rtState, roundResults, rt, batch)
}

func (n *Node) schedulerStoreTransactions(ctx context.Context, blk *block.Block, inputWriteLog storage.WriteLog, inputRoot hash.Hash) error {
	var emptyRoot hash.Hash
	emptyRoot.Empty()

	return n.storage.Apply(ctx, &storage.ApplyRequest{
		Namespace: blk.Header.Namespace,
		RootType:  storage.RootTypeIO,
		SrcRound:  blk.Header.Round + 1,
		SrcRoot:   emptyRoot,
		DstRound:  blk.Header.Round + 1,
		DstRoot:   inputRoot,
		WriteLog:  inputWriteLog,
	})
}

func (n *Node) schedulerCreateProposalLocked(ctx context.Context, inputRoot hash.Hash, txHashes []hash.Hash) (*commitment.Proposal, error) {
	blk := n.commonNode.CurrentBlock

	// Create new proposal.
	proposal := &commitment.Proposal{
		NodeID: n.commonNode.Identity.NodeSigner.Public(),
		Header: commitment.ProposalHeader{
			Round:        blk.Header.Round + 1,
			PreviousHash: blk.Header.EncodedHash(),
			BatchHash:    inputRoot,
		},
		Batch: txHashes,
	}
	if err := proposal.Sign(n.commonNode.Identity.NodeSigner, blk.Header.Namespace); err != nil {
		return nil, fmt.Errorf("failed to sign proposal header: %w", err)
	}

	n.logger.Debug("dispatching a new batch proposal",
		"input_root", inputRoot,
		"batch_size", len(txHashes),
	)

	n.commonNode.P2P.Publish(ctx, n.committeeTopic, &p2p.CommitteeMessage{
		Epoch:    n.commonNode.CurrentEpoch,
		Proposal: proposal,
	})
	crash.Here(crashPointBatchPublishAfter)
	return proposal, nil
}

func (n *Node) startRuntimeBatchSchedulingLocked(
	rtState *roothash.RuntimeState,
	roundResults *roothash.RoundResults,
	rt host.RichRuntime,
	batch []*txpool.TxQueueMeta,
) {
	n.logger.Debug("asking runtime to schedule batch",
		"initial_batch_size", len(batch),
	)

	// Create batch processing context and channel for receiving the response.
	ctx, cancel := context.WithCancel(n.roundCtx)
	done := make(chan *processedBatch, 1)

	batchStartTime := time.Now()
	n.transitionLocked(StateProcessingBatch{&unresolvedBatch{}, batchStartTime, cancel, done, protocol.ExecutionModeSchedule})

	// Request the worker host to process a batch. This is done in a separate
	// goroutine so that the committee node can continue processing blocks.
	blk := n.commonNode.CurrentBlock
	consensusBlk := n.commonNode.CurrentConsensusBlock
	epoch := n.commonNode.CurrentEpoch

	go func() {
		defer close(done)

		initialBatch := make([][]byte, 0, len(batch))
		for _, tx := range batch {
			initialBatch = append(initialBatch, tx.Raw())
		}

		// Ask the runtime to execute the batch.
		rsp, err := n.runtimeExecuteTxBatch(
			ctx,
			rt,
			protocol.ExecutionModeSchedule,
			epoch,
			consensusBlk,
			blk,
			rtState,
			roundResults,
			hash.Hash{}, // IORoot is ignored as it is yet to be determined.
			initialBatch,
		)
		if err != nil {
			n.logger.Error("runtime batch execution failed",
				"err", err,
			)
			return
		}

		// Remove any rejected transactions.
		n.commonNode.TxPool.HandleTxsUsed(rsp.TxRejectHashes)
		// Mark any proposed transactions.
		n.commonNode.TxPool.PromoteProposedBatch(rsp.TxHashes)

		// Submit response to the executor worker.
		done <- &processedBatch{
			computed:        &rsp.Batch,
			txHashes:        rsp.TxHashes,
			txInputRoot:     rsp.TxInputRoot,
			txInputWriteLog: rsp.TxInputWriteLog,
		}
	}()
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
		if ok && state.discrepancyDetected {
			// We have already received a discrepancy event, start processing immediately.
			n.logger.Info("already received a discrepancy event, start processing batch")
			n.startProcessingBatchLocked(batch)
			return
		}

		// Immediately resolve the batch so that we are ready when needed.
		switch resolvedBatch, err := n.resolveBatchLocked(batch, StateWaitingForEvent{batch}); {
		case err != nil:
			// TODO: We should indicate failure.
			return
		case resolvedBatch == nil:
			// Missing transactions, batch processing will start once all are available.
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

func (n *Node) runtimeExecuteTxBatch(
	ctx context.Context,
	rt host.RichRuntime,
	mode protocol.ExecutionMode,
	epoch beacon.EpochTime,
	consensusBlk *consensus.LightBlock,
	blk *block.Block,
	state *roothash.RuntimeState,
	roundResults *roothash.RoundResults,
	inputRoot hash.Hash,
	inputs transaction.RawBatch,
) (*protocol.RuntimeExecuteTxBatchResponse, error) {
	// Ensure block round is synced to storage.
	n.logger.Debug("ensuring block round is synced", "round", blk.Header.Round)
	if _, err := n.commonNode.Runtime.History().WaitRoundSynced(ctx, blk.Header.Round); err != nil {
		return nil, err
	}

	// Fetch any incoming messages.
	inMsgs, err := n.commonNode.Consensus.RootHash().GetIncomingMessageQueue(ctx, &roothash.InMessageQueueRequest{
		RuntimeID: n.commonNode.Runtime.ID(),
		Height:    consensusBlk.Height,
	})
	if err != nil {
		n.logger.Error("failed to fetch incoming runtime message queue metadata",
			"err", err,
		)
		return nil, err
	}

	rq := &protocol.Body{
		RuntimeExecuteTxBatchRequest: &protocol.RuntimeExecuteTxBatchRequest{
			Mode:           mode,
			ConsensusBlock: *consensusBlk,
			RoundResults:   roundResults,
			IORoot:         inputRoot,
			Inputs:         inputs,
			InMessages:     inMsgs,
			Block:          *blk,
			Epoch:          epoch,
			MaxMessages:    state.Runtime.Executor.MaxMessages,
		},
	}
	batchSize.With(n.getMetricLabels()).Observe(float64(len(inputs)))

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
		return nil, fmt.Errorf("batch processing aborted by context")
	default:
		n.logger.Error("error while sending batch processing request to runtime",
			"err", err,
		)
		return nil, err
	}
	crash.Here(crashPointBatchProcessStartAfter)

	if rsp.RuntimeExecuteTxBatchResponse == nil {
		n.logger.Error("malformed response from runtime",
			"response", rsp,
		)
		return nil, fmt.Errorf("malformed response from runtime")
	}

	return rsp.RuntimeExecuteTxBatchResponse, nil
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) startProcessingBatchLocked(batch *unresolvedBatch) {
	if n.commonNode.CurrentBlock == nil {
		panic("attempted to start processing batch with a nil block")
	}

	// Try to resolve the batch first.
	resolvedBatch, err := n.resolveBatchLocked(batch, StateWaitingForTxs{batch})
	switch {
	case err != nil:
		// TODO: We should indicate failure.
		return
	case resolvedBatch == nil:
		// Missing transactions, we will be called again once all are available.
		return
	}

	n.logger.Debug("processing batch",
		"batch_size", len(resolvedBatch),
	)

	// Create batch processing context and channel for receiving the response.
	ctx, cancel := context.WithCancel(n.roundCtx)
	done := make(chan *processedBatch, 1)

	batchStartTime := time.Now()
	n.transitionLocked(StateProcessingBatch{batch, batchStartTime, cancel, done, protocol.ExecutionModeExecute})

	rt := n.commonNode.GetHostedRuntime()
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
	epoch := n.commonNode.CurrentEpoch

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

		// Ask the runtime to execute the batch.
		rsp, err := n.runtimeExecuteTxBatch(
			ctx,
			rt,
			protocol.ExecutionModeExecute,
			epoch,
			consensusBlk,
			blk,
			state,
			roundResults,
			batch.hash(),
			resolvedBatch,
		)
		if err != nil {
			n.logger.Error("runtime batch execution failed",
				"err", err,
			)
			return
		}

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
			computed: &rsp.Batch,
			raw:      resolvedBatch,
			txHashes: rsp.TxHashes,
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
		"io_root", *batch.Header.IORoot,
		"state_root", *batch.Header.StateRoot,
		"messages_hash", *batch.Header.MessagesHash,
		"in_msgs_hash", *batch.Header.InMessagesHash,
		"in_msgs_count", batch.Header.InMessagesCount,
	)

	// Generate executor commitment.
	rakSig := batch.RakSig
	ec := &commitment.ExecutorCommitment{
		NodeID: n.commonNode.Identity.NodeSigner.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			Header:       batch.Header,
			RAKSignature: &rakSig,
		},
	}
	// If we are the transaction scheduler also include all the emitted messages.
	if epoch.IsTransactionScheduler(lastHeader.Round) {
		ec.Messages = batch.Messages
	}

	var inputRoot hash.Hash
	switch {
	case unresolved.proposal == nil:
		inputRoot = processed.txInputRoot
	default:
		inputRoot = unresolved.hash()
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
			SrcRoot:   inputRoot,
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
		ec.Header.SetFailure(commitment.FailureUnknown)
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

	if err := n.signAndSubmitCommitment(roundCtx, ec); err != nil {
		n.logger.Error("failed to sign and submit the commitment",
			"commit", ec,
			"err", err,
		)
		n.abortBatchLocked(err)
		return
	}

	// Due to backwards compatibility with runtimes that don't provide transaction hashes as output
	// we need to manually compute them here.
	if len(processed.raw) > 0 && len(processed.txHashes) == 0 {
		processed.txHashes = make([]hash.Hash, 0, len(processed.raw))
		for _, tx := range processed.raw {
			processed.txHashes = append(processed.txHashes, hash.NewFromBytes(tx))
		}
	}

	switch storageErr {
	case nil:
		n.transitionLocked(StateWaitingForFinalize{
			batchStartTime: state.batchStartTime,
			proposedIORoot: *ec.Header.Header.IORoot,
			txHashes:       processed.txHashes,
		})
	default:
		n.abortBatchLocked(storageErr)
	}

	crash.Here(crashPointBatchProposeAfter)
}

func (n *Node) signAndSubmitCommitment(roundCtx context.Context, ec *commitment.ExecutorCommitment) error {
	err := ec.Sign(n.commonNode.Identity.NodeSigner, n.commonNode.Runtime.ID())
	if err != nil {
		n.logger.Error("failed to sign commitment",
			"commit", ec,
			"err", err,
		)
		return err
	}

	tx := roothash.NewExecutorCommitTx(0, nil, n.commonNode.Runtime.ID(), []commitment.ExecutorCommitment{*ec})
	go func() {
		commitErr := consensus.SignAndSubmitTx(roundCtx, n.commonNode.Consensus, n.commonNode.Identity.NodeSigner, tx)
		switch commitErr {
		case nil:
			n.logger.Info("executor commit finalized")
		default:
			n.logger.Error("failed to submit executor commit",
				"commit", ec,
				"err", commitErr,
			)
		}
	}()

	return nil
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) handleProposalLocked(batch *unresolvedBatch) error {
	n.logger.Debug("handling a new batch proposal",
		"proposer", batch.proposal.NodeID,
		"round", batch.proposal.Header.Round,
	)

	// TODO: Handle proposal equivocation.

	if _, ok := n.state.(StateWaitingForBatch); !ok { //nolint:revive
		// Currently not waiting for batch.
	} else if epoch := n.commonNode.Group.GetEpochSnapshot(); !epoch.IsExecutorMember() { //nolint:revive
		// Currently not an executor committee member.
	} else {
		// Maybe process if we have the correct block.
		currentHash := n.commonNode.CurrentBlock.Header.EncodedHash()
		if currentHash.Equal(&batch.proposal.Header.PreviousHash) {
			n.maybeStartProcessingBatchLocked(batch)
			return nil // Forward proposal.
		}
	}

	// When checks fail, add proposal into the queue of pending proposals for later retry.
	return n.addPendingProposalLocked(batch)
}

// nudgeAvailabilityLocked checks whether the executor worker should declare itself available.
func (n *Node) nudgeAvailabilityLocked(force bool) {
	// Check availability of the last round which is needed for round processing.
	_, _, err := n.getRtStateAndRoundResults(n.ctx, consensus.HeightLatest)
	lastRoundAvailable := (err == nil)

	// Make sure the key manager is available (or not needed).
	var keymanagerAvailable bool
	select {
	case <-n.commonNode.KeyManagerClient.Initialized():
		keymanagerAvailable = true
	default:
	}

	switch {
	case n.runtimeReady && lastRoundAvailable && n.runtimeTrustSynced && keymanagerAvailable:
		// Executor is ready to process requests.
		if n.roleProvider.IsAvailable() && !force {
			break
		}

		n.roleProvider.SetAvailable(func(nd *node.Node) error {
			for _, version := range n.commonNode.Runtime.HostVersions() {
				// Skip sending any old versions that will never be active again.
				if version.ToU64() < n.runtimeVersion.ToU64() {
					continue
				}

				// Obtain CapabilityTEE for the given runtime version.
				capabilityTEE, err := n.commonNode.GetHostedRuntimeCapabilityTEE(version)
				if err != nil {
					n.logger.Warn("failed to get CapabilityTEE for hosted runtime, skipping",
						"err", err,
						"version", version,
					)
					continue
				}

				rt := nd.AddOrUpdateRuntime(n.commonNode.Runtime.ID(), version)
				rt.Capabilities.TEE = capabilityTEE
			}
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

func (n *Node) HandleRuntimeHostEventLocked(ev *host.Event) {
	switch {
	case ev.Started != nil:
		// Make sure the runtime supports all the required features.
		n.runtimeReady = false
		n.runtimeTrustSynced = false

		ctx, cancel := context.WithTimeout(n.ctx, getInfoTimeout)
		defer cancel()
		rt := n.commonNode.GetHostedRuntime()
		if rt == nil {
			n.logger.Error("failed to retrieve runtime information")
			break
		}
		rtInfo, err := rt.GetInfo(ctx)
		if err != nil {
			n.logger.Error("failed to retrieve runtime information", "err", err)
			break
		}
		if !rtInfo.Features.HasScheduleControl() {
			n.logger.Error("runtime does not support schedule control")
			break
		}

		// If the runtime has a trust root configured, make sure we are able to successfully sync
		// the runtime up to the latest height as otherwise request processing will fail.
		n.startRuntimeTrustSyncLocked(rt)

		// We are now able to service requests for this runtime.
		n.runtimeReady = true
		n.runtimeVersion = ev.Started.Version
	case ev.Updated != nil:
		// Update runtime capabilities.
		n.runtimeReady = true
	case ev.FailedToStart != nil, ev.Stopped != nil:
		// Runtime failed to start or was stopped -- we can no longer service requests.
		n.runtimeReady = false

		// Cancel any outstanding runtime light client sync.
		n.cancelRuntimeTrustSyncLocked()
	case ev.ConfigUpdated != nil:
		// Configuration updated, just refresh availability.
	default:
		// Unknown event.
		n.logger.Warn("unknown worker event",
			"ev", ev,
		)
	}

	n.nudgeAvailabilityLocked(true)
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

	switch {
	case batch == nil || batch.computed == nil:
		// There was an issue during batch processing.
	case state.mode == protocol.ExecutionModeSchedule:
		// Scheduling was processed successfully.
		n.logger.Info("runtime has finished scheduling a batch",
			"input_root", batch.txInputRoot,
			"tx_hashes", batch.txHashes,
		)
		err := n.schedulerStoreTransactions(roundCtx, n.commonNode.CurrentBlock, batch.txInputWriteLog, batch.txInputRoot)
		if err != nil {
			n.logger.Error("failed to store transaction",
				"err", err,
			)
			break
		}

		// Create and submit a proposal.
		_, err = n.schedulerCreateProposalLocked(roundCtx, batch.txInputRoot, batch.txHashes)
		if err != nil {
			n.logger.Error("failed to create proposal",
				"err", err,
			)
			break
		}
		fallthrough
	default:
		// Batch was processed successfully.
		stateBatch := state.batch
		n.commonNode.CrossNode.Unlock()
		n.logger.Info("worker has finished processing a batch")
		n.proposeBatch(roundCtx, &lastHeader, stateBatch, batch)
		return
	}

	defer n.commonNode.CrossNode.Unlock()

	// Unsuccessful batch processing.
	n.logger.Warn("worker has aborted batch processing")
	commit := &commitment.ExecutorCommitment{
		NodeID: n.commonNode.Identity.NodeSigner.Public(),
		Header: commitment.ExecutorCommitmentHeader{
			Header: commitment.ComputeResultsHeader{
				Round:        lastHeader.Round + 1,
				PreviousHash: lastHeader.EncodedHash(),
			},
		},
	}
	commit.Header.SetFailure(commitment.FailureUnknown)

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

	// Subscribe to notifications of new transactions being available in the pool.
	txSub, txCh := n.commonNode.TxPool.WatchCheckedTransactions()
	defer txSub.Close()

	// Subscribe to scheduler notifications.
	schedSub, schedCh := n.commonNode.TxPool.WatchScheduler()
	defer schedSub.Close()

	// Subscribe to gossiped executor commitments.
	ecCh, ecSub, err := n.commonNode.Consensus.RootHash().WatchExecutorCommitments(n.ctx)
	if err != nil {
		n.logger.Error("failed to subscribe to executor commitments",
			"err", err,
		)
		close(n.initCh)
		return
	}
	defer ecSub.Close()

	// We are initialized.
	close(n.initCh)

	// Update availability once keymanager client initializes.
	go func() {
		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case <-n.commonNode.KeyManagerClient.Initialized():
			n.commonNode.CrossNode.Lock()
			n.nudgeAvailabilityLocked(false)
			n.commonNode.CrossNode.Unlock()
		}
	}()

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
		case batch := <-processingDoneCh:
			// Batch processing has finished.
			n.handleProcessedBatch(batch, processingDoneCh)
		case force := <-schedCh:
			// Attempt scheduling.
			n.handleScheduleBatch(force)
		case txs := <-txCh:
			// Check any queued transactions.
			n.handleNewCheckedTransactions(txs)
		case ec := <-ecCh:
			// Process observed executor commitments.
			n.handleObservedExecutorCommitment(ec)
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
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	committeeTopic := p2pProtocol.NewTopicKindCommitteeID(commonNode.ChainContext, commonNode.Runtime.ID())

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		commonNode:       commonNode,
		commonCfg:        commonCfg,
		roleProvider:     roleProvider,
		committeeTopic:   committeeTopic,
		pendingProposals: newPendingProposals(),
		ctx:              ctx,
		cancelCtx:        cancel,
		stopCh:           make(chan struct{}),
		quitCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		state:            StateNotReady{},
		txSync:           txsync.NewClient(commonNode.P2P, commonNode.ChainContext, commonNode.Runtime.ID()),
		stateTransitions: pubsub.NewBroker(false),
		reselect:         make(chan struct{}, 1),
		logger:           logging.GetLogger("worker/executor/committee").With("runtime_id", commonNode.Runtime.ID()),
	}

	// Register prune handler.
	commonNode.Runtime.History().Pruner().RegisterHandler(&pruneHandler{commonNode: commonNode})

	// Register committee message handler.
	commonNode.P2P.RegisterHandler(committeeTopic, &committeeMsgHandler{n})

	return n, nil
}
