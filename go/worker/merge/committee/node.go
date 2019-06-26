package committee

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
)

var (
	errIncorrectState = errors.New("merge: incorrect state")
	errSeenNewerBlock = errors.New("merge: seen newer block")
	errMergeFailed    = errors.New("merge: failed to perform merge")
)

var (
	discrepancyDetectedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_merge_discrepancy_detected_count",
			Help: "Number of detected merge discrepancies",
		},
		[]string{"runtime"},
	)
	roothashCommitLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_worker_roothash_merge_commit_latency",
			Help: "Latency of roothash merge commit",
		},
		[]string{"runtime"},
	)
	abortedMergeCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_aborted_merge_count",
			Help: "Number of aborted merges",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		discrepancyDetectedCount,
		roothashCommitLatency,
		abortedMergeCount,
	}

	metricsOnce sync.Once

	infiniteTimeout = time.Duration(math.MaxInt64)
)

// Config is a committee node configuration.
type Config struct {
	// TODO: Move this to common worker config.
	StorageCommitTimeout time.Duration

	ByzantineInjectDiscrepancies bool
}

// Node is a committee node.
type Node struct { // nolint: maligned
	commonNode *committee.Node

	cfg Config

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
		"runtime": n.commonNode.RuntimeID.String(),
	}
}

// HandlePeerMessage implements NodeHooks.
func (n *Node) HandlePeerMessage(ctx context.Context, message *p2p.Message) (bool, error) {
	if message.ComputeWorkerFinished != nil {
		n.commonNode.CrossNode.Lock()
		defer n.commonNode.CrossNode.Unlock()

		m := message.ComputeWorkerFinished
		err := n.handleResultsLocked(ctx, &m.Commitment)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
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

func (n *Node) newStateWaitingForResultsLocked(epoch *committee.EpochSnapshot) StateWaitingForResults {
	pool := &commitment.MultiPool{
		Committees: make(map[hash.Hash]*commitment.Pool),
	}

	for cID, ci := range epoch.GetComputeCommittees() {
		nodeInfo := make(map[signature.MapKey]commitment.NodeInfo, len(ci.Nodes))
		for idx, nd := range ci.Nodes {
			var nodeRuntime *node.Runtime
			for _, r := range nd.Runtimes {
				if !r.ID.Equal(n.commonNode.RuntimeID) {
					continue
				}
				nodeRuntime = r
				break
			}
			if nodeRuntime == nil {
				// We currently prevent this case throughout the rest of the system.
				// Still, it's prudent to check.
				n.logger.Warn("committee member not registered with this runtime",
					"node", nd.ID,
				)
				continue
			}

			nodeInfo[nd.ID.ToMapKey()] = commitment.NodeInfo{
				CommitteeNode: idx,
				Runtime:       nodeRuntime,
			}
		}

		pool.Committees[cID] = &commitment.Pool{
			Runtime:   epoch.GetRuntime(),
			Committee: ci.Committee,
			NodeInfo:  nodeInfo,
		}
	}

	return StateWaitingForResults{
		pool:  pool,
		timer: time.NewTimer(infiniteTimeout),
	}
}

// HandleEpochTransitionLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleEpochTransitionLocked(epoch *committee.EpochSnapshot) {
	if epoch.IsMergeWorker() || epoch.IsMergeBackupWorker() {
		n.transitionLocked(n.newStateWaitingForResultsLocked(epoch))
	} else {
		n.transitionLocked(StateNotReady{})
	}
}

// HandleNewBlockEarlyLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(blk *block.Block) {
	// If we have seen a new block while waiting for results, we need to
	// abort it no matter what as any processed state may be invalid.
	n.abortMergeLocked(errSeenNewerBlock)
}

// HandleNewBlockLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewBlockLocked(blk *block.Block) {
	epoch := n.commonNode.Group.GetEpochSnapshot()

	// Perform actions based on current state.
	switch n.state.(type) {
	case StateWaitingForEvent:
		// Block finalized without the need for a backup worker.
		n.logger.Info("considering the round finalized",
			"round", blk.Header.Round,
			"header_hash", blk.Header.EncodedHash(),
		)
		n.transitionLocked(n.newStateWaitingForResultsLocked(epoch))
	case StateWaitingForFinalize:
		// A new block means the round has been finalized.
		n.logger.Info("considering the round finalized",
			"round", blk.Header.Round,
			"header_hash", blk.Header.EncodedHash(),
		)
		n.transitionLocked(n.newStateWaitingForResultsLocked(epoch))
	}
}

// HandleResultsFromComputeWorkerLocked processes results from a compute worker.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleResultsFromComputeWorkerLocked(spanCtx opentracing.SpanContext, commit *commitment.ComputeCommitment) {
	// TODO: Context.
	if err := n.handleResultsLocked(context.TODO(), commit); err != nil {
		n.logger.Warn("failed to handle results from local compute worker",
			"err", err,
		)
	}
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) handleResultsLocked(ctx context.Context, commit *commitment.ComputeCommitment) error {
	// If we are not waiting for results, don't do anything.
	state, ok := n.state.(StateWaitingForResults)
	if !ok {
		return errIncorrectState
	}

	n.logger.Debug("received new compute commitment")

	sp, err := state.pool.AddComputeCommitment(n.commonNode.CurrentBlock, commit)
	if err != nil {
		return err
	}

	n.tryFinalizeResultsLocked(sp, false)
	return nil
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) tryFinalizeResultsLocked(pool *commitment.Pool, didTimeout bool) {
	state := n.state.(StateWaitingForResults)
	now := time.Now()

	defer func() {
		if !didTimeout && !state.timer.Stop() {
			<-state.timer.C
		}

		nextTimeout := state.pool.GetNextTimeout()
		if nextTimeout.IsZero() {
			// Disarm timer.
			n.logger.Debug("disarming round timeout")
			state.timer.Reset(infiniteTimeout)
		} else {
			// (Re-)arm timer.
			n.logger.Debug("(re-)arming round timeout")
			state.timer.Reset(nextTimeout.Sub(now))
		}
	}()

	// NOTE: The roothash backend will start counting its timeout on its own based on
	//       any received commits so in the worst case the actual timeout will be
	//       2*roundTimeout.
	roundTimeout := n.commonNode.Roothash.Info().ComputeRoundTimeout

	logger := n.logger.With("committee_id", pool.GetCommitteeID())
	commit, err := pool.TryFinalize(now, roundTimeout, didTimeout)
	switch err {
	case nil:
	case commitment.ErrStillWaiting:
		// Not enough commitments.
		logger.Debug("still waiting for commitments")
		return
	case commitment.ErrDiscrepancyDetected:
		// We may also be able to already perform discrepancy resolution, check if
		// this is possible. This may be the case if we receive commits from backup
		// workers before receiving commits from regular workers.
		commit, err = pool.TryFinalize(now, roundTimeout, false)
		if err == nil {
			// Discrepancy was already resolved, proceed with merge.
			break
		}

		// Discrepancy detected.
		fallthrough
	case commitment.ErrInsufficientVotes:
		// Discrepancy resolution failed.
		logger.Warn("insufficient votes, performing CC-Commit")

		// Submit CC-Commit to BFT.
		err = n.commonNode.Roothash.ComputeCommit(n.ctx, n.commonNode.RuntimeID, pool.GetComputeCommitments())
		if err != nil {
			// NOTE: This may happen just because someone else just submitted
			//       the same CC-Commit. It is safe to ignore this error.
			logger.Warn("failed to submit CC-Commit",
				"err", err,
			)
		}
		return
	default:
		n.abortMergeLocked(err)
		return
	}

	// Check that we have everything from all committees.
	result := commit.ToDDResult().(commitment.ComputeResultsHeader)
	state.results = append(state.results, &result)
	if len(state.results) < len(state.pool.Committees) {
		n.logger.Debug("still waiting for other committees")
		// State transition to store the updated results.
		n.transitionLocked(state)
		return
	}

	n.logger.Info("have valid commitments from all committees, merging")

	epoch := n.commonNode.Group.GetEpochSnapshot()

	commitments := state.pool.GetComputeCommitments()

	if epoch.IsMergeBackupWorker() {
		// Backup workers only perform merge after receiving a discrepancy event.
		n.transitionLocked(StateWaitingForEvent{commitments: commitments, results: state.results})
		return
	}

	// No discrepancy, perform merge.
	n.startMergeLocked(commitments, state.results)
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) startMergeLocked(commitments []commitment.ComputeCommitment, results []*commitment.ComputeResultsHeader) {
	doneCh := make(chan *commitment.MergeBody, 1)
	ctx, cancel := context.WithCancel(n.ctx)

	// Create empty block based on previous block while we hold the lock.
	blk := block.NewEmptyBlock(n.commonNode.CurrentBlock, 0, block.Normal)
	stateRoot := n.commonNode.CurrentBlock.Header.StateRoot

	n.transitionLocked(StateProcessingMerge{doneCh: doneCh, cancel: cancel})

	// Start processing merge in a separate goroutine. This is to make it possible
	// to abort the merge if a newer block is seen while we are merging.
	go func() {
		defer close(doneCh)

		// TODO: Actually merge (#1823).
		_ = stateRoot
		blk.Header.IORoot = results[0].IORoot
		blk.Header.StateRoot = results[0].StateRoot

		// Merge results to storage.
		ctx, cancel = context.WithTimeout(ctx, n.cfg.StorageCommitTimeout)
		defer cancel()

		// NOTE: Order is important for verifying the receipt.
		applyOps := []storage.ApplyOp{
			// I/O root.
			storage.ApplyOp{
				Root:            blk.Header.IORoot,
				ExpectedNewRoot: blk.Header.IORoot,
				WriteLog:        make(storage.WriteLog, 0),
			},
			// State root.
			storage.ApplyOp{
				Root:            blk.Header.StateRoot,
				ExpectedNewRoot: blk.Header.StateRoot,
				WriteLog:        make(storage.WriteLog, 0),
			},
		}

		receipts, err := n.commonNode.Storage.ApplyBatch(ctx, applyOps)
		if err != nil {
			n.logger.Error("failed to apply to storage",
				"err", err,
			)
			return
		}

		// TODO: Ensure that the receipt is actually signed by storage nodes.
		// For now accept a signature from anyone.
		signatures := []signature.Signature{}
		for _, receipt := range receipts {
			var receiptBody storage.ReceiptBody
			if err = receipt.Open(&receiptBody); err != nil {
				n.logger.Error("failed to open receipt",
					"receipt", receipt,
					"err", err,
				)
				return
			}
			if err = blk.Header.VerifyStorageReceipt(&receiptBody); err != nil {
				n.logger.Error("failed to validate receipt body",
					"receipt body", receiptBody,
					"err", err,
				)
				return
			}
			signatures = append(signatures, receipt.Signature)
		}
		blk.Header.StorageSignatures = signatures

		n.byzantineMaybeInjectDiscrepancy(&blk.Header)

		doneCh <- &commitment.MergeBody{
			ComputeCommits: commitments,
			Header:         blk.Header,
		}
	}()
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) proposeHeaderLocked(result *commitment.MergeBody) {
	n.logger.Debug("proposing header",
		"previous_hash", result.Header.PreviousHash,
		"round", result.Header.Round,
	)

	// Submit MC-Commit to BFT for DD and finalization.
	mc, err := commitment.SignMergeCommitment(*n.commonNode.Identity.NodeKey, result)
	if err != nil {
		n.logger.Error("failed to sign merge commitment",
			"err", err,
		)
		n.abortMergeLocked(err)
		return
	}

	n.transitionLocked(StateWaitingForFinalize{})

	// TODO: Tracing.
	// span := opentracing.StartSpan("roothash.MergeCommit", opentracing.ChildOf(state.batchSpanCtx))
	// defer span.Finish()

	start := time.Now()
	mcs := []commitment.MergeCommitment{*mc}
	err = n.commonNode.Roothash.MergeCommit(n.ctx, n.commonNode.RuntimeID, mcs)
	if err != nil {
		n.logger.Error("failed to submit MC-Commit",
			"err", err,
		)
		n.abortMergeLocked(err)
		return
	}

	roothashCommitLatency.With(n.getMetricLabels()).Observe(time.Since(start).Seconds())
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) abortMergeLocked(reason error) {
	switch state := n.state.(type) {
	case StateWaitingForResults:
	case StateProcessingMerge:
		// Cancel merge processing.
		state.cancel()
	default:
		return
	}

	n.logger.Warn("aborting merge",
		"reason", reason,
	)

	// TODO: Return transactions to transaction scheduler.

	abortedMergeCount.With(n.getMetricLabels()).Inc()

	// After the batch has been aborted, we must wait for the round to be
	// finalized.
	n.transitionLocked(StateWaitingForFinalize{})
}

// HandleNewEventLocked implements NodeHooks.
// Guarded by n.commonNode.CrossNode.
func (n *Node) HandleNewEventLocked(ev *roothash.Event) {
	dis := ev.MergeDiscrepancyDetected
	if dis == nil {
		// Ignore other events.
		return
	}

	// If we are not waiting for an event, don't do anything.
	state, ok := n.state.(StateWaitingForEvent)
	if !ok {
		return
	}

	n.logger.Warn("merge discrepancy detected")

	discrepancyDetectedCount.With(n.getMetricLabels()).Inc()

	if !n.commonNode.Group.GetEpochSnapshot().IsMergeBackupWorker() {
		return
	}

	// Backup worker, start processing merge.
	n.logger.Info("backup worker activating and processing merge")
	n.startMergeLocked(state.commitments, state.results)
}

func (n *Node) worker() {
	// Delay starting of committee node until after the consensus service
	// has finished initial synchronization, if applicable.
	if n.commonNode.Consensus != nil {
		n.logger.Info("delaying committee node start until after initial synchronization")
		select {
		case <-n.quitCh:
			return
		case <-n.commonNode.Consensus.Synced():
		}
	}
	n.logger.Info("starting committee node")

	defer close(n.quitCh)
	defer (n.cancelCtx)()

	// We are initialized.
	close(n.initCh)

	for {
		// Select over some channels based on current state.
		var timerCh <-chan time.Time
		var mergeDoneCh <-chan *commitment.MergeBody
		func() {
			n.commonNode.CrossNode.Lock()
			defer n.commonNode.CrossNode.Unlock()

			switch state := n.state.(type) {
			case StateWaitingForResults:
				timerCh = state.timer.C
			case StateProcessingMerge:
				mergeDoneCh = state.doneCh
			default:
			}
		}()

		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case <-timerCh:
			n.logger.Warn("round timeout expired, forcing finalization")

			func() {
				n.commonNode.CrossNode.Lock()
				defer n.commonNode.CrossNode.Unlock()

				state, ok := n.state.(StateWaitingForResults)
				if !ok {
					return
				}

				for _, pool := range state.pool.GetTimeoutCommittees(time.Now()) {
					n.tryFinalizeResultsLocked(pool, true)
				}
			}()
		case result := <-mergeDoneCh:
			func() {
				n.commonNode.CrossNode.Lock()
				defer n.commonNode.CrossNode.Unlock()

				if result == nil {
					n.logger.Warn("merge aborted")
					n.abortMergeLocked(errMergeFailed)
				} else {
					n.logger.Info("merge completed, proposing header")
					n.proposeHeaderLocked(result)
				}
			}()
		case <-n.reselect:
			// Recalculate select set.
		}
	}
}

func NewNode(
	commonNode *committee.Node,
	cfg Config,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		commonNode:       commonNode,
		cfg:              cfg,
		ctx:              ctx,
		cancelCtx:        cancel,
		stopCh:           make(chan struct{}),
		quitCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		state:            StateNotReady{},
		stateTransitions: pubsub.NewBroker(false),
		reselect:         make(chan struct{}, 1),
		logger:           logging.GetLogger("worker/merge/committee").With("runtime_id", commonNode.RuntimeID),
	}

	return n, nil
}
