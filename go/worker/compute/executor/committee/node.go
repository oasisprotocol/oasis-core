package committee

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"golang.org/x/exp/maps"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	p2pProtocol "github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	commonWorker "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p/txsync"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

var (
	errMsgFromNonTxnSched = fmt.Errorf("executor: received txn scheduler dispatch msg from non-txn scheduler")

	// abortTimeout is the duration to wait for the runtime to abort.
	abortTimeout = 5 * time.Second
	// getInfoTimeout is the maximum time the runtime can spend replying to GetInfo.
	getInfoTimeout = 5 * time.Second
)

// executeBatchTimeoutFactor is the factor F in calculation of the batch execution timeout using
// the formula F * ProposerTimeout to ensure that a broken runtime doesn't block forever.
const executeBatchTimeoutFactor = 3

// Node is a committee node.
type Node struct {
	runtimeReady         bool
	runtimeTrustSynced   bool
	runtimeTrustSyncCncl context.CancelFunc

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

	storage storage.LocalBackend
	txSync  txsync.Client

	// Global, used by every round worker.

	state            NodeState
	stateTransitions *pubsub.Broker
	proposals        *proposalQueue
	committee        *scheduler.Committee
	commitPool       *commitment.Pool

	blockInfoCh      chan *runtime.BlockInfo
	processedBatchCh chan *processedBatch
	reselectCh       chan struct{}
	missingTxCh      chan [][]byte

	txCh <-chan []*txpool.PendingCheckTransaction
	ecCh <-chan *commitment.ExecutorCommitment
	evCh <-chan *roothash.Event

	// Local, set and used by every round worker.

	rt            host.RichRuntime
	epoch         *committee.EpochSnapshot
	blockInfo     *runtime.BlockInfo
	rtState       *roothash.RuntimeState
	roundResults  *roothash.RoundResults
	discrepancy   *discrepancyEvent
	submitted     map[uint64]struct{}
	rank          uint64
	poolRank      uint64
	proposedBatch *proposedBatch

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

func (n *Node) reselect() {
	select {
	case n.reselectCh <- struct{}{}:
	default:
		// If there's one already queued, we don't need to do anything.
	}
}

func (n *Node) transitionState(state NodeState) {
	n.logger.Info("state transition",
		"current_state", n.state,
		"new_state", state,
	)

	// Validate state transition.
	dests := validStateTransitions[n.state.Name()]

	if !slices.Contains(dests[:], state.Name()) {
		panic(fmt.Sprintf("invalid state transition: %s -> %s", n.state, state))
	}

	n.state = state
	n.stateTransitions.Broadcast(state)
}

func (n *Node) transitionStateToProcessing(ctx context.Context, proposal *commitment.Proposal, rank uint64, batch transaction.RawBatch) {
	ctx, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})

	n.transitionState(StateProcessingBatch{
		mode:           protocol.ExecutionModeExecute,
		rank:           rank,
		batchStartTime: time.Now(),
		cancelFn:       cancel,
		done:           done,
	})

	// Request the worker host to process a batch. This is done in a separate
	// goroutine so that the runtime worker can continue processing events.
	go func() {
		defer close(done)
		n.startProcessingBatch(ctx, proposal, rank, batch)
	}()
}

func (n *Node) transitionStateToProcessingFailure(
	proposal *commitment.Proposal,
	rank uint64,
	bytes uint64,
	maxBytes uint64,
	batchSize uint64,
	maxBatchSize uint64,
) {
	n.logger.Debug("batch too large",
		"bytes", bytes,
		"max_bytes", maxBytes,
		"batch_size", batchSize,
		"max_batch_size", maxBatchSize,
	)

	cancel := func(_ error) {}
	done := make(chan struct{})
	close(done)

	n.transitionState(StateProcessingBatch{
		mode:           protocol.ExecutionModeExecute,
		rank:           rank,
		batchStartTime: time.Now(),
		cancelFn:       cancel,
		done:           done,
	})

	// Submit response to the round worker.
	n.processedBatchCh <- &processedBatch{
		proposal: proposal,
		rank:     rank,
		computed: nil,
	}
}

func (n *Node) updateState(ctx context.Context, minRank uint64, maxRank uint64, discrepancy bool) {
	switch state := n.state.(type) {
	case StateWaitingForBatch:
		// Nothing to be done here.
	case StateWaitingForTxs:
		switch {
		case state.rank < minRank || state.rank > maxRank:
			// Rank ouf ot bounds; stop fetching.
			state.Cancel()
			n.transitionState(StateWaitingForBatch{})
		case state.maxBytes > 0 && state.bytes > state.maxBytes:
			// Some transactions have been received, but the batch is too large; stop fetching and
			// submit failure.
			state.Cancel()

			// All workers should indicate failure immediately.
			n.transitionStateToProcessingFailure(state.proposal, state.rank, state.bytes, state.maxBytes, state.batchSize, state.maxBatchSize)
		case len(state.txs) == 0:
			// All transactions have been received; stop fetching and start processing.
			state.Cancel()

			// The backup workers should process only if the discrepancy was detected.
			if !n.epoch.IsExecutorWorker() && n.epoch.IsExecutorBackupWorker() && !discrepancy {
				n.transitionState(StateWaitingForEvent{
					proposal: state.proposal,
					rank:     state.rank,
					batch:    state.batch,
				})
				return
			}

			n.transitionStateToProcessing(ctx, state.proposal, state.rank, state.batch)
		default:
			// Keep on waiting for transactions.
		}
	case StateWaitingForEvent:
		if state.rank < minRank || state.rank > maxRank {
			// Rank ouf ot bounds; stop fetching.
			n.transitionState(StateWaitingForBatch{})
			return
		}
		if discrepancy {
			// Discrepancy detected; stop waiting and start processing.
			n.transitionStateToProcessing(ctx, state.proposal, state.rank, state.batch)
			return
		}
	case StateProcessingBatch:
		if state.rank < minRank || state.rank > maxRank {
			// Rank ouf ot bounds; stop processing.
			n.abortBatch(&state)
			n.transitionState(StateWaitingForBatch{})
			return
		}
	}
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

func (n *Node) scheduleBatch(ctx context.Context, round uint64, force bool) {
	n.logger.Debug("trying to schedule a batch",
		"round", round,
		"rank", n.rank,
		"force", force,
		"state", n.state.Name(),
	)

	// Check if we are in a suitable state for scheduling a batch.
	switch n.state.(type) {
	case StateWaitingForBatch:
	default:
		return
	}

	// Schedule only once.
	if _, ok := n.submitted[n.rank]; ok {
		n.logger.Debug("not scheduling, commitment already submitted")
		return
	}

	// Only executor workers are permitted to schedule batches.
	if !n.epoch.IsExecutorWorker() {
		n.logger.Debug("not scheduling, not an executor")
		return
	}

	// If the next block will be an epoch transition block, do not propose anything as it will be
	// reverted anyway (since the committee will change).
	epochState, err := n.commonNode.Consensus.Beacon().GetFutureEpoch(ctx, n.blockInfo.ConsensusBlock.Height)
	if err != nil {
		n.logger.Error("failed to fetch future epoch state",
			"err", err,
		)
		return
	}
	if epochState != nil && epochState.Height == n.blockInfo.ConsensusBlock.Height+1 {
		n.logger.Debug("not scheduling, next consensus block is an epoch transition")
		return
	}

	// Fetch incoming message queue metadata to see if there's any queued messages.
	inMsgMeta, err := n.commonNode.Consensus.RootHash().GetIncomingMessageQueueMeta(ctx, &roothash.RuntimeRequest{
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
	rtInfo, err := n.rt.GetInfo(ctx)
	if err != nil {
		n.logger.Warn("not scheduling, the runtime is broken",
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
	batch := n.commonNode.TxPool.GetSchedulingSuggestion(int(rtInfo.Features.ScheduleControl.InitialBatchSize))
	switch {
	case force:
		// Batch flush timeout expired, schedule empty batch.
	case len(batch) > 0:
		// We have some transactions, schedule batch.
	case len(n.roundResults.Messages) > 0:
		// We have runtime message results (and batch timeout expired), schedule batch.
	case inMsgMeta.Size > 0:
		// We have queued incoming runtime messages (and batch timeout expired), schedule batch.
	case n.rtState.LastNormalRound == n.rtState.GenesisBlock.Header.Round:
		// This is the runtime genesis, schedule batch.
	default:
		// No need to schedule a batch.
		n.logger.Debug("not scheduling, no transactions")
		return
	}

	ctx, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})

	n.transitionState(StateProcessingBatch{
		mode:           protocol.ExecutionModeSchedule,
		rank:           n.rank,
		batchStartTime: time.Now(),
		cancelFn:       cancel,
		done:           done,
	})

	// Request the worker host to schedule a batch. This is done in a separate
	// goroutine so that the runtime worker can continue processing events.
	go func() {
		defer close(done)
		n.startSchedulingBatch(ctx, batch)
	}()
}

func (n *Node) publishProposal(ctx context.Context, proposal *commitment.Proposal) error {
	if err := proposal.Sign(n.commonNode.Identity.NodeSigner, n.commonNode.Runtime.ID()); err != nil {
		return fmt.Errorf("failed to sign proposal header: %w", err)
	}

	n.logger.Debug("dispatching a new batch proposal",
		"input_root", proposal.Header.BatchHash,
		"batch_size", len(proposal.Batch),
	)

	n.commonNode.P2P.Publish(ctx, n.committeeTopic, &p2p.CommitteeMessage{
		Epoch:    n.epoch.GetEpochNumber(),
		Proposal: proposal,
	})

	crash.Here(crashPointBatchPublishAfter)

	return nil
}

func (n *Node) startSchedulingBatch(ctx context.Context, batch []*txpool.TxQueueMeta) {
	// This method runs within its own goroutine and is always stopped before the runtime
	// worker finishes. Therefore, it is safe to read local round variables (block info, ...).
	n.logger.Debug("scheduling batch",
		"batch_size", len(batch),
	)

	initialBatch := make([][]byte, 0, len(batch))
	for _, tx := range batch {
		initialBatch = append(initialBatch, tx.Raw())
	}

	// Ask the runtime to execute the batch.
	rsp, err := n.runtimeExecuteTxBatch(
		ctx,
		n.rt,
		protocol.ExecutionModeSchedule,
		n.blockInfo.Epoch,
		n.blockInfo.ConsensusBlock,
		n.blockInfo.RuntimeBlock,
		n.blockInfo.IncomingMessages,
		n.rtState,
		n.roundResults,
		hash.Hash{}, // IORoot is ignored as it is yet to be determined.
		initialBatch,
	)
	if err != nil {
		n.logger.Error("runtime batch execution failed",
			"err", err,
		)
		// Notify the round worker that the execution failed.
		n.processedBatchCh <- nil
		return
	}

	// Remove any rejected transactions.
	n.commonNode.TxPool.RejectTxs(rsp.TxRejectHashes)
	// Mark any proposed transactions.
	_, _ = n.commonNode.TxPool.PromoteProposedBatch(rsp.TxHashes)

	// Create new proposal.
	proposal := commitment.Proposal{
		NodeID: n.commonNode.Identity.NodeSigner.Public(),
		Header: commitment.ProposalHeader{
			Round:        n.blockInfo.RuntimeBlock.Header.Round + 1,
			PreviousHash: n.blockInfo.RuntimeBlock.Header.EncodedHash(),
			BatchHash:    rsp.TxInputRoot,
		},
		Batch: rsp.TxHashes,
	}

	// Submit response to the round worker.
	n.processedBatchCh <- &processedBatch{
		proposal:        &proposal,
		rank:            n.rank,
		computed:        &rsp.Batch,
		txInputWriteLog: rsp.TxInputWriteLog,
	}
}

func (n *Node) runtimeExecuteTxBatch(
	ctx context.Context,
	rt host.RichRuntime,
	mode protocol.ExecutionMode,
	epoch beacon.EpochTime,
	consensusBlk *consensus.LightBlock,
	blk *block.Block,
	inMsgs []*message.IncomingMessage,
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

	// Ensure batch execution is bounded.
	//
	// Note: We intentionally never abort batch execution when ctx is canceled
	// (e.g., when a round ends or when a proposal with a higher rank is received)
	// to prevent runtimes from restarting, as abort requests are currently not
	// supported. Execution shouldn't take a significant amount of time anyway
	// unless something is seriously wrong.
	proposerTimeout := state.Runtime.TxnScheduler.ProposerTimeout
	callCtx, cancelCallFn := context.WithTimeoutCause(
		context.TODO(), // Replace with ctx once runtimes start supporting abort requests.
		executeBatchTimeoutFactor*proposerTimeout,
		errors.New("proposer timeout expired"),
	)
	defer cancelCallFn()

	rsp, err := rt.Call(callCtx, rq)
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// Context was canceled while the runtime was processing a request.
		n.logger.Error("batch processing aborted by context, restarting runtime",
			"cause", context.Cause(callCtx),
		)

		// Abort the runtime, so we can start processing the next batch. Note that we use the global
		// node context here to make sure abort gets processed even when ctx has been cancelled.
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

func (n *Node) startProcessingBatch(ctx context.Context, proposal *commitment.Proposal, rank uint64, batch transaction.RawBatch) {
	// This method runs within its own goroutine and is always stopped before the runtime
	// worker finishes. Therefore, it is safe to read local round variables (block info, ...).
	n.logger.Debug("processing batch",
		"batch_size", len(batch),
	)

	// Ask the runtime to execute the batch.
	rsp, err := n.runtimeExecuteTxBatch(
		ctx,
		n.rt,
		protocol.ExecutionModeExecute,
		n.blockInfo.Epoch,
		n.blockInfo.ConsensusBlock,
		n.blockInfo.RuntimeBlock,
		n.blockInfo.IncomingMessages,
		n.rtState,
		n.roundResults,
		proposal.Header.BatchHash,
		batch,
	)
	if err != nil {
		n.logger.Error("runtime batch execution failed",
			"err", err,
		)
		// Notify the round worker that the execution failed.
		n.processedBatchCh <- nil
		return
	}

	// Submit response to the round worker.
	n.processedBatchCh <- &processedBatch{
		proposal:        proposal,
		rank:            rank,
		computed:        &rsp.Batch,
		txInputWriteLog: rsp.TxInputWriteLog,
	}
}

func (n *Node) abortBatch(state *StateProcessingBatch) {
	n.logger.Warn("aborting processing batch")

	// Stop processing.
	state.Cancel(errors.New("batch aborted"))

	// Discard the result if there was any.
	select {
	case <-n.processedBatchCh:
	default:
	}

	crash.Here(crashPointBatchAbortAfter)

	abortedBatchCount.With(n.getMetricLabels()).Inc()
}

func (n *Node) proposeBatch(
	roundCtx context.Context,
	lastHeader *block.Header,
	processed *processedBatch,
) {
	crash.Here(crashPointBatchProposeBefore)

	batch := processed.computed

	n.logger.Debug("proposing batch",
		"scheduler_id", processed.proposal.NodeID,
		"node_id", n.commonNode.Identity.NodeSigner.Public(),
		"batch_size", len(processed.proposal.Batch),
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
			SchedulerID:  processed.proposal.NodeID,
			Header:       batch.Header,
			RAKSignature: &rakSig,
		},
	}
	// If we are the transaction scheduler also include all the emitted messages.
	if ec.NodeID.Equal(ec.Header.SchedulerID) {
		ec.Messages = batch.Messages
	}

	// Commit I/O and state write logs to storage.
	storageErr := func() error {
		start := time.Now()
		defer func() {
			storageCommitLatency.With(n.getMetricLabels()).Observe(time.Since(start).Seconds())
		}()

		ctx, cancel := context.WithCancel(roundCtx)
		defer cancel()

		// Store final I/O root.
		var emptyRoot hash.Hash
		emptyRoot.Empty()

		err := n.storage.Apply(ctx, &storage.ApplyRequest{
			Namespace: lastHeader.Namespace,
			RootType:  storage.RootTypeIO,
			SrcRound:  lastHeader.Round + 1,
			SrcRoot:   emptyRoot,
			DstRound:  lastHeader.Round + 1,
			DstRoot:   *batch.Header.IORoot,
			WriteLog:  append(processed.txInputWriteLog, batch.IOWriteLog...),
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

		// Ensure storage is written to disk before signing a commitment.
		return n.storage.NodeDB().Sync()
	}()
	if storageErr != nil {
		n.logger.Error("storage failure, submitting failure indicating commitment",
			"err", storageErr,
		)
		ec.Header.SetFailure(commitment.FailureUnknown)
	}

	// Submit commitment.
	// Make sure we are still in the right state/round.
	state, ok := n.state.(StateProcessingBatch)
	if !ok || lastHeader.Round != n.blockInfo.RuntimeBlock.Header.Round {
		n.logger.Error("new state or round since started proposing batch",
			"state", state,
			"round", n.blockInfo.RuntimeBlock.Header.Round,
			"expected_round", lastHeader.Round,
		)
		return
	}

	n.logger.Debug("sign and submit the commitment",
		"commit", ec,
	)

	if err := n.signAndSubmitCommitment(roundCtx, ec); err != nil {
		n.logger.Error("failed to sign and submit the commitment",
			"commit", ec,
			"err", err,
		)
		n.abortBatch(&state)
		return
	}

	n.submitted[processed.rank] = struct{}{}

	if storageErr != nil {
		n.abortBatch(&state)
		n.transitionState(StateWaitingForBatch{})
		return
	}

	n.proposedBatch = &proposedBatch{
		batchStartTime: state.batchStartTime,
		proposedIORoot: *ec.Header.Header.IORoot,
		txHashes:       processed.proposal.Batch,
	}

	n.transitionState(StateWaitingForBatch{})

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

func (n *Node) processProposal(ctx context.Context, proposal *commitment.Proposal, rank uint64, discrepancy bool) {
	n.logger.Debug("trying to process a proposal",
		"scheduler", proposal.NodeID,
		"round", proposal.Header.Round,
		"rank", rank,
		"discrepancy", discrepancy,
	)

	// Check if we are in a suitable state for processing a proposal.
	switch n.state.(type) {
	case StateWaitingForBatch:
	default:
		n.logger.Debug("not processing, invalid state",
			"state", n.state.Name(),
		)
		return
	}

	// Process only once.
	if _, ok := n.submitted[rank]; ok {
		n.logger.Debug("not processing, commitment already submitted")
		return
	}

	switch discrepancy {
	case true:
		// Only backup executor workers are permitted to process batches.
		if !n.epoch.IsExecutorBackupWorker() {
			n.logger.Debug("not processing, not a backup executor")
			return
		}
	case false:
		// All workers are allowed to process batches. The only difference is that the backup
		// execution workers will wait for a discrepancy event before beginning execution.
	}

	n.logger.Debug("attempting to resolve batch")

	// Try to resolve the batch first.
	// TODO: Add metrics for how long it takes to receive the complete batch.
	resolvedBatch, missingTxs := n.commonNode.TxPool.PromoteProposedBatch(proposal.Batch)

	// Compute batch size.
	batchSize := uint64(len(proposal.Batch))
	bytes := uint64(0)
	for _, tx := range resolvedBatch {
		if tx == nil {
			continue
		}
		bytes += uint64(tx.Size())
	}

	// Submit failure if the batch is invalid.
	// The scheduler is violating the protocol and should be punished.
	maxBatchSize := n.blockInfo.ActiveDescriptor.TxnScheduler.MaxBatchSize
	maxBytes := n.blockInfo.ActiveDescriptor.TxnScheduler.MaxBatchSizeBytes
	if batchSize > maxBatchSize || maxBytes > 0 && bytes > maxBytes {
		n.transitionStateToProcessingFailure(proposal, rank, bytes, maxBytes, batchSize, maxBatchSize)
		return
	}

	// Prepare the batch. If some transactions are missing, they will be filled latter.
	batch := make(transaction.RawBatch, 0, len(resolvedBatch))
	for _, tx := range resolvedBatch {
		switch tx {
		case nil:
			batch = append(batch, nil)
		default:
			batch = append(batch, tx.Raw())
		}
	}

	// Missing transactions, we will wait until all are received.
	if len(missingTxs) > 0 {
		n.logger.Debug("some transactions are missing", "num_missing", len(missingTxs))

		txHashes := maps.Keys(missingTxs)

		subCtx, cancelFn := context.WithCancel(ctx)
		done := make(chan struct{})

		n.transitionState(StateWaitingForTxs{
			proposal:     proposal,
			rank:         rank,
			batch:        batch,
			txs:          missingTxs,
			bytes:        bytes,
			maxBytes:     maxBytes,
			batchSize:    batchSize,
			maxBatchSize: maxBatchSize,
			cancelFn:     cancelFn,
			done:         done,
		})

		go func() {
			defer close(done)
			n.requestMissingTransactions(subCtx, txHashes)
		}()

		return
	}

	// TODO: Handle proposal equivocation.

	// Maybe process if we have the correct block.
	currentHash := n.blockInfo.RuntimeBlock.Header.EncodedHash()
	if !currentHash.Equal(&proposal.Header.PreviousHash) {
		return
	}

	// The backup workers should process only if the discrepancy was detected.
	if !n.epoch.IsExecutorWorker() && n.epoch.IsExecutorBackupWorker() && !discrepancy {
		n.transitionState(StateWaitingForEvent{
			proposal: proposal,
			rank:     rank,
			batch:    batch,
		})
		return
	}

	n.transitionStateToProcessing(ctx, proposal, rank, batch)
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

		n.roleProvider.SetAvailable(n.commonNode.RegisterNodeRuntime)
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
		n.startRuntimeTrustSyncLocked(host.NewRichRuntime(rt))

		// We are now able to service requests for this runtime.
		n.runtimeReady = true
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

func (n *Node) handleProcessedBatch(ctx context.Context, batch *processedBatch) {
	state, ok := n.state.(StateProcessingBatch)
	if !ok {
		// Should not be possible, as we always drain the channel once we transition
		// to a different state.
		n.logger.Error("failed to handle processed batch, invalid state",
			"state", n.state,
		)
		return
	}
	lastHeader := n.blockInfo.RuntimeBlock.Header

	// A nil batch indicates that scheduling or processing has failed.
	// Return to the initial state and retry.
	if batch == nil {
		n.transitionState(StateWaitingForBatch{})
		return
	}

	// Check if there was an issue during batch processing.
	if batch.computed == nil {
		n.logger.Warn("worker has aborted batch processing")

		n.abortBatch(&state)
		n.transitionState(StateWaitingForBatch{})

		commit := &commitment.ExecutorCommitment{
			NodeID: n.commonNode.Identity.NodeSigner.Public(),
			Header: commitment.ExecutorCommitmentHeader{
				SchedulerID: batch.proposal.NodeID,
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
		if err := n.signAndSubmitCommitment(ctx, commit); err != nil {
			n.logger.Error("failed to sign and submit the commitment",
				"commit", commit,
				"err", err,
			)
			return
		}

		n.submitted[batch.rank] = struct{}{}
		return
	}

	// Check if scheduling was processed successfully.
	if state.mode == protocol.ExecutionModeSchedule {
		n.logger.Info("runtime has finished scheduling a batch",
			"input_root", batch.proposal.Header.BatchHash,
			"tx_hashes", batch.proposal.Batch,
		)

		// Sign and submit the proposal to P2P network.
		err := n.publishProposal(ctx, batch.proposal)
		if err != nil {
			n.logger.Error("failed to sign and publish proposal",
				"err", err,
			)
			return
		}
	}

	// Batch was processed successfully.
	n.logger.Info("worker has finished processing a batch")
	n.proposeBatch(ctx, &lastHeader, batch)
}

func (n *Node) handleEvent(ctx context.Context, ev *roothash.Event) {
	processedEventCount.With(n.getMetricLabels()).Inc()

	switch {
	case ev.ExecutionDiscrepancyDetected != nil:
		n.handleDiscrepancy(ctx, &discrepancyEvent{
			height:        uint64(ev.Height),
			round:         ev.ExecutionDiscrepancyDetected.Round,
			rank:          ev.ExecutionDiscrepancyDetected.Rank,
			timeout:       ev.ExecutionDiscrepancyDetected.Timeout,
			authoritative: true,
		})
	case ev.ExecutorCommitted != nil:
		n.handleExecutorCommitment(ctx, &ev.ExecutorCommitted.Commit)
	}
}

func (n *Node) handleExecutorCommitment(ctx context.Context, ec *commitment.ExecutorCommitment) {
	n.logger.Debug("executor commitment",
		"commitment", ec,
	)

	id := n.commonNode.Identity.NodeSigner.Public()
	switch {
	case n.committee.IsWorker(id):
		n.estimatePoolRank(ctx, ec, false)
	}
}

func (n *Node) handleObservedExecutorCommitment(ctx context.Context, ec *commitment.ExecutorCommitment) {
	n.logger.Debug("observed executor commitment",
		"commitment", ec,
	)

	id := n.commonNode.Identity.NodeSigner.Public()
	switch {
	case n.committee.IsWorker(id):
		n.estimatePoolRank(ctx, ec, true)
	case n.committee.IsBackupWorker(id):
		n.predictDiscrepancy(ctx, ec)
	}
}

func (n *Node) estimatePoolRank(ctx context.Context, ec *commitment.ExecutorCommitment, observed bool) {
	// Filter for this round only.
	round := n.blockInfo.RuntimeBlock.Header.Round + 1
	if ec.Header.Header.Round != round {
		n.logger.Debug("ignoring bad executor commitment, not for this round",
			"round", round,
			"ec_round", ec.Header.Header.Round,
			"node_id", ec.NodeID,
			"observed", observed,
		)
		return
	}

	// Filter scheduler commitments.
	if ec.NodeID != ec.Header.SchedulerID {
		n.logger.Debug("ignoring bad executor commitment, not from scheduler",
			"node_id", ec.NodeID,
			"observed", observed,
		)
		return
	}

	if observed {
		// Verify the commitment.
		rt := n.epoch.GetRuntime()
		if err := commitment.VerifyExecutorCommitment(ctx, n.blockInfo.RuntimeBlock, rt, n.committee.ValidFor, ec, nil, n.epoch); err != nil {
			n.logger.Debug("ignoring bad executor commitment, verification failed",
				"err", err,
				"node_id", ec.NodeID,
				"observed", observed,
			)
			return
		}
	}

	// Update pool rank.
	rank, ok := n.committee.SchedulerRank(ec.Header.Header.Round, ec.Header.SchedulerID)
	if !ok {
		n.logger.Debug("ignoring bad executor commitment, scheduler not in committee",
			"node_id", ec.NodeID,
			"observed", observed,
		)
		return
	}
	if rank >= n.poolRank {
		return
	}
	n.poolRank = rank
	n.logger.Debug("pool rank has changed",
		"round", round,
		"rank", n.poolRank,
		"observed", observed,
	)
}

func (n *Node) finalizePreviousRound() {
	n.logger.Info("considering the round finalized",
		"round", n.blockInfo.RuntimeBlock.Header.Round,
		"header_hash", n.blockInfo.RuntimeBlock.Header.EncodedHash(),
		"header_type", n.blockInfo.RuntimeBlock.Header.HeaderType,
	)

	if n.proposedBatch != nil && n.blockInfo.RuntimeBlock.Header.HeaderType == block.Normal {
		switch n.blockInfo.RuntimeBlock.Header.IORoot.Equal(&n.proposedBatch.proposedIORoot) {
		case false:
			n.logger.Error("proposed batch was not finalized",
				"header_io_root", n.blockInfo.RuntimeBlock.Header.IORoot,
				"proposed_io_root", n.proposedBatch.proposedIORoot,
				"header_type", n.blockInfo.RuntimeBlock.Header.HeaderType,
				"batch_size", len(n.proposedBatch.txHashes),
			)
		case true:
			// Record time taken for successfully processing a batch.
			batchProcessingTime.With(n.getMetricLabels()).Observe(time.Since(n.proposedBatch.batchStartTime).Seconds())

			n.logger.Debug("removing processed batch from queue",
				"batch_size", len(n.proposedBatch.txHashes),
				"io_root", n.blockInfo.RuntimeBlock.Header.IORoot,
			)

			// Remove processed transactions from queue.
			n.commonNode.TxPool.HandleTxsUsed(n.proposedBatch.txHashes)
		}
	}

	// Clear last proposal.
	n.proposedBatch = nil

	// Clear proposal queue.
	n.commonNode.TxPool.ClearProposedBatch()
}

// resetNodeState transitions to the StateWaitingForBatch state.
func (n *Node) resetNodeState() {
	switch state := n.state.(type) {
	case StateWaitingForBatch:
		// Nothing to do here.
		return
	case StateWaitingForTxs:
		// Stop waiting for transactions.
		n.logger.Warn("considering the round failed due to missing transactions")
		state.Cancel()
	case StateWaitingForEvent:
		// Block finalized without the need for a backup worker.
		n.logger.Info("considering the round finalized without backup worker")
	case StateProcessingBatch:
		n.abortBatch(&state)
	}

	n.transitionState(StateWaitingForBatch{})
}

// drainChannels clears all worker's channels.
//
// This ensures that channels do not accumulate obsolete data when the round worker exits
// early due to non-membership in the executor committee or errors.
func (n *Node) drainChannels(ctx context.Context) {
	for {
		select {
		case <-n.txCh:
		case <-n.ecCh:
		case <-n.evCh:
		case <-n.reselectCh:
		case <-ctx.Done():
			return
		}
	}
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

	n.logger.Info("starting worker")

	var (
		err   error
		txSub pubsub.ClosableSubscription
		ecSub pubsub.ClosableSubscription
		evSub pubsub.ClosableSubscription
	)

	// Subscribe to notifications of new transactions being available in the pool.
	n.txCh, txSub = n.commonNode.TxPool.WatchCheckedTransactions()
	defer txSub.Close()

	// Subscribe to gossiped executor commitments.
	n.ecCh, ecSub, err = n.commonNode.Consensus.RootHash().WatchExecutorCommitments(n.ctx, n.commonNode.Runtime.ID())
	if err != nil {
		n.logger.Error("failed to subscribe to executor commitments",
			"err", err,
		)
		close(n.initCh)
		return
	}
	defer ecSub.Close()

	// Start watching roothash events.
	n.evCh, evSub, err = n.commonNode.Consensus.RootHash().WatchEvents(n.ctx, n.commonNode.Runtime.ID())
	if err != nil {
		n.logger.Error("failed to subscribe to roothash events",
			"err", err,
		)
		return
	}
	defer evSub.Close()

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

	// Restart the round worker every time a runtime block is finalized.
	for {
		var bi *runtime.BlockInfo

		func() {
			var wg sync.WaitGroup
			defer wg.Wait()

			ctx, cancel := context.WithCancelCause(n.ctx)
			defer cancel(errors.New("round finished"))

			wg.Go(func() {
				n.roundWorker(ctx)
				n.drainChannels(ctx)
			})

			select {
			case <-n.stopCh:
			case bi = <-n.blockInfoCh:
			}
		}()

		// Round worker stopped, so it is safe to update the last block info.
		n.blockInfo = bi

		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		default:
		}
	}
}

func (n *Node) roundWorker(ctx context.Context) {
	if n.blockInfo == nil {
		return
	}
	round := n.blockInfo.RuntimeBlock.Header.Round + 1

	n.logger.Debug("round worker started",
		"round", round,
	)
	defer n.logger.Debug("round worker stopped",
		"round", round,
	)

	n.finalizePreviousRound()
	defer n.resetNodeState()

	// Prune proposals.
	n.proposals.Prune(round)

	// Need to be an executor committee member.
	n.epoch = n.commonNode.Group.GetEpochSnapshot()
	if !n.epoch.IsExecutorMember() {
		n.logger.Debug("skipping round, not an executor member",
			"round", round,
		)
		return
	}

	// This should never fail as we only register to be an executor worker
	// once the hosted runtime is ready.
	rt := n.commonNode.GetHostedRuntime()
	if rt == nil {
		n.logger.Error("skipping round, hosted runtime is not yet initialized")
		return
	}
	n.rt = host.NewRichRuntime(rt)

	// Fetch state and round results upfront.
	var err error
	n.rtState, n.roundResults, err = n.getRtStateAndRoundResults(ctx, n.blockInfo.ConsensusBlock.Height)
	if err != nil {
		n.logger.Debug("skipping round, failed to fetch state and round results",
			"err", err,
		)
		return
	}

	// Prepare flush timer for the primary transaction scheduler.
	flush := false
	flushTimer := time.NewTimer(n.blockInfo.ActiveDescriptor.TxnScheduler.BatchFlushTimeout)
	defer flushTimer.Stop()

	// Compute node's rank when scheduling transactions.
	id := n.commonNode.Identity.NodeSigner.Public()
	n.committee = n.epoch.GetExecutorCommittee().Committee
	n.rank = math.MaxUint64
	if rank, ok := n.committee.SchedulerRank(round, id); ok {
		n.rank = rank
	}

	n.logger.Debug("node is an executor member",
		"round", round,
		"rank", n.rank,
		"worker", n.epoch.IsExecutorWorker(),
		"backup_worker", n.epoch.IsExecutorBackupWorker(),
	)

	// Estimate the pool's highest rank to prevent committing to worse-ranked proposals
	// that will be rejected by the pool.
	n.poolRank = uint64(math.MaxUint64)

	// Allow only the highest-ranked scheduler to propose immediately.
	schedulerRank := uint64(0)

	// The ticker determines when we are allowed to commit to proposals from schedulers
	// with lower ranks.
	schedulerRankTicker := time.NewTicker(n.rtState.Runtime.TxnScheduler.ProposerTimeout)
	defer schedulerRankTicker.Stop()

	// Reset discrepancy detection.
	n.discrepancy = nil
	n.commitPool = commitment.NewPool()

	// Reset submitted proposals/commitments.
	n.submitted = make(map[uint64]struct{})

	// Main loop.
	for {
		// Update state, propose or schedule.
		switch n.discrepancy {
		case nil:
			limit := min(schedulerRank, n.poolRank, n.rank)
			proposal, rank, ok := n.proposals.Best(round, 0, limit, n.submitted)
			switch {
			case ok && rank < n.rank:
				// Commit to a proposal with a higher rank.
				n.updateState(ctx, 0, rank, false)
				n.processProposal(ctx, proposal, rank, false)
			case n.rank <= limit:
				// Try to schedule a batch.
				n.updateState(ctx, 0, n.rank, false)
				n.scheduleBatch(ctx, round, flush)
			}
		default:
			n.updateState(ctx, n.discrepancy.rank, n.discrepancy.rank, true)

			limit := n.discrepancy.rank
			proposal, rank, ok := n.proposals.Best(round, limit, limit, n.submitted)
			switch {
			case ok:
				// Try to process the discrepant proposal.
				n.processProposal(ctx, proposal, rank, true)
			case n.rank == n.discrepancy.rank:
				// Try to schedule a batch.
				n.scheduleBatch(ctx, round, true)
			}
		}

		select {
		case <-ctx.Done():
			n.logger.Debug("exiting round, context canceled")
			return
		case ev := <-n.evCh:
			// Handle an event.
			n.handleEvent(ctx, ev)
		case txs := <-n.txCh:
			// Check any queued transactions.
			n.handleNewCheckedTransactions(txs)
		case txs := <-n.missingTxCh:
			// Missing transactions fetched.
			n.handleMissingTransactions(txs)
		case ec := <-n.ecCh:
			// Process observed executor commitments.
			n.handleObservedExecutorCommitment(ctx, ec)
		case batch := <-n.processedBatchCh:
			// Batch processing has either finished or failed.
			n.handleProcessedBatch(ctx, batch)
		case <-schedulerRankTicker.C:
			// Change scheduler rank and try again.
			schedulerRank++
			n.logger.Debug("scheduler rank has changed",
				"rank", schedulerRank,
			)
		case <-flushTimer.C:
			// Force scheduling for primary transaction scheduler.
			n.logger.Debug("scheduling is now forced")
			flush = true
		case <-n.reselectCh:
			// Try again.
		}
	}
}

// NewNode initializes a new executor node.
func NewNode(
	commonNode *committee.Node,
	commonCfg commonWorker.Config,
	roleProvider registration.RoleProvider,
) (*Node, error) {
	initMetrics()

	committeeTopic := p2pProtocol.NewTopicKindCommitteeID(commonNode.ChainContext, commonNode.Runtime.ID())

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		commonNode:       commonNode,
		commonCfg:        commonCfg,
		roleProvider:     roleProvider,
		committeeTopic:   committeeTopic,
		proposals:        newPendingProposals(),
		ctx:              ctx,
		cancelCtx:        cancel,
		stopCh:           make(chan struct{}),
		quitCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		state:            StateWaitingForBatch{},
		txSync:           txsync.NewClient(commonNode.P2P, commonNode.ChainContext, commonNode.Runtime.ID()),
		stateTransitions: pubsub.NewBroker(false),
		blockInfoCh:      make(chan *runtime.BlockInfo, 1),
		processedBatchCh: make(chan *processedBatch, 1),
		reselectCh:       make(chan struct{}, 1),
		missingTxCh:      make(chan [][]byte, 1),
		logger:           logging.GetLogger("worker/executor/committee").With("runtime_id", commonNode.Runtime.ID()),
	}

	// Register committee message handler.
	commonNode.P2P.RegisterHandler(committeeTopic, &committeeMsgHandler{n})

	return n, nil
}
