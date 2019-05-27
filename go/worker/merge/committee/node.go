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
	"github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
)

var (
	errIncorrectState = errors.New("merge: incorrect state")
	errSeenNewerBlock = errors.New("merge: seen newer block")
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

func (n *Node) newStateWaitingForResultsLocked(epoch *committee.EpochSnapshot) StateWaitingForResults {
	committee := epoch.GetComputeCommittee()
	nodes := epoch.GetComputeNodes()
	cID := committee.EncodedMembersHash()
	nodeInfo := make(map[signature.MapKey]commitment.NodeInfo, len(nodes))
	for idx, nd := range nodes {
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

	pool := &commitment.MultiPool{
		Committees: map[hash.Hash]*commitment.Pool{
			cID: &commitment.Pool{
				Runtime:   epoch.GetRuntime(),
				Committee: committee,
				NodeInfo:  nodeInfo,
			},
		},
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
	// Perform actions based on current state.
	switch n.state.(type) {
	case StateWaitingForFinalize:
		// A new block means the round has been finalized.
		n.logger.Info("considering the round finalized")

		epoch := n.commonNode.Group.GetEpochSnapshot()
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
	header, err := pool.TryFinalize(now, roundTimeout, didTimeout)
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
		header, err = pool.TryFinalize(now, roundTimeout, false)
		if err == nil {
			// Discrepancy was already resolved, proceed with merge.
			break
		}

		// Discrepancy detected.
		fallthrough
	case commitment.ErrInsufficientVotes:
		// Discrepancy resolution failed.
		logger.Warn("compute discrepancy detected, performing CC-Commit")

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

	// TODO: Check that we have everything from all committees (#1775).

	n.logger.Info("have valid commitments from all committees, merging")

	epoch := n.commonNode.Group.GetEpochSnapshot()

	commitments := state.pool.GetComputeCommitments()
	// TODO: Collect headers from all committees (#1775).
	headers := []*block.Header{header}

	if epoch.IsMergeBackupWorker() {
		// Backup workers only perform merge after receiving a discrepancy event.
		n.transitionLocked(StateWaitingForEvent{commitments: commitments, headers: headers})
		return
	}

	// No discrepancy, perform merge.
	n.startMergeLocked(commitments, headers)
}

// Guarded by n.commonNode.CrossNode.
func (n *Node) startMergeLocked(commitments []commitment.ComputeCommitment, headers []*block.Header) {
	// TODO: Actually merge, currently we don't have anything to merge as there
	//       is only a single committee (#1775).

	// TODO: Make sure that merge is performed in the background to not block.

	n.byzantineMaybeInjectDiscrepancy(headers)

	// Submit MC-Commit to BFT for DD and finalization.
	mc, err := commitment.SignMergeCommitment(*n.commonNode.Identity.NodeKey, &commitment.MergeBody{
		ComputeCommits: commitments,
		Header:         *headers[0],
	})
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
	_, ok := n.state.(StateWaitingForResults)
	if !ok {
		// We can only abort if we are waiting for results.
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
	n.startMergeLocked(state.commitments, state.headers)
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

	// TODO: Add timer for merge round timeout.

	for {
		// Check if we are currently waiting for results. In this case we also
		// need to select over the timer channel.
		var timerCh <-chan time.Time
		func() {
			n.commonNode.CrossNode.Lock()
			defer n.commonNode.CrossNode.Unlock()
			if state, ok := n.state.(StateWaitingForResults); ok {
				timerCh = state.timer.C
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
		logger:           logging.GetLogger("worker/merge/committee").With("runtime_id", commonNode.RuntimeID),
	}

	return n, nil
}
