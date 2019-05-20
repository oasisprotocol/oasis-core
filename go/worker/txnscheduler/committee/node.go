package committee

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/common/crash"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/common/tracing"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/committee"
	"github.com/oasislabs/ekiden/go/worker/common/p2p"
	computeCommittee "github.com/oasislabs/ekiden/go/worker/compute/committee"
)

var (
	ErrNotLeader = errors.New("not leader")
)

var (
	incomingQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ekiden_worker_txnscheduler_incoming_queue_size",
			Help: "Size of the incoming queue (number of entries)",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		incomingQueueSize,
	}

	metricsOnce sync.Once
)

// Config is a committee node configuration.
type Config struct {
	MaxQueueSize      uint64
	MaxBatchSize      uint64
	MaxBatchSizeBytes uint64
	MaxBatchTimeout   time.Duration
}

// Node is a committee node.
type Node struct {
	commonNode  *committee.Node
	computeNode *computeCommittee.Node

	cfg Config

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	stopOnce  sync.Once
	quitCh    chan struct{}
	initCh    chan struct{}

	incomingQueue *incomingQueue

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
		"runtime": n.commonNode.RuntimeID.String(),
	}
}

// HandlePeerMessage implements NodeHooks.
func (n *Node) HandlePeerMessage(ctx context.Context, message p2p.Message) (bool, error) {
	return false, nil
}

// QueueCall queues a call for processing by this node.
func (n *Node) QueueCall(ctx context.Context, call []byte) error {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.commonNode.Group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
		return ErrNotLeader
	}

	if err := n.incomingQueue.Add(call); err != nil {
		// Return success in case of duplicate calls to avoid the client
		// mistaking this for an actual error.
		if err == errCallAlreadyExists {
			n.logger.Warn("ignoring duplicate call",
				"call", hex.EncodeToString(call),
			)
			return nil
		}

		return err
	}

	incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.incomingQueue.Size()))

	return nil
}

// IsTransactionQueued checks if the given transaction is present in the
// transaction scheduler queue and is waiting to be dispatched to a
// compute committee.
func (n *Node) IsTransactionQueued(ctx context.Context, id hash.Hash) (bool, error) {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.commonNode.Group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
		return false, ErrNotLeader
	}

	return n.incomingQueue.IsQueued(id), nil
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
	if epoch.IsTransactionSchedulerLeader() {
		n.transitionLocked(StateWaitingForBatch{})
	} else {
		n.incomingQueue.Clear()
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

// Guarded by n.commonNode.CrossNode.
func (n *Node) checkIncomingQueueLocked(force bool) {
	// If we are not waiting for a batch, don't do anything.
	if _, ok := n.state.(StateWaitingForBatch); !ok {
		return
	}

	epoch := n.commonNode.Group.GetEpochSnapshot()
	// If we are not a leader or we don't have any blocks, don't do anything.
	if !epoch.IsTransactionSchedulerLeader() || n.commonNode.CurrentBlock == nil {
		return
	}

	batch, err := n.incomingQueue.Take(force)
	if err != nil {
		return
	}
	var processOk bool
	defer func() {
		if !processOk {
			// Put the batch back into the incoming queue in case this failed.
			if errAB := n.incomingQueue.AddBatch(batch); errAB != nil {
				n.logger.Error("failed to add batch back into the incoming queue",
					"err", errAB,
				)
			}
		}

		incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.incomingQueue.Size()))
	}()

	// Leader node opens a new parent span for batch processing.
	batchSpan := opentracing.StartSpan("TakeBatchFromQueue(batch)",
		opentracing.Tag{Key: "batch", Value: batch},
	)
	defer batchSpan.Finish()
	batchSpanCtx := batchSpan.Context()

	spanInsert, ctx := tracing.StartSpanWithContext(n.ctx, "Insert(batch)",
		opentracing.Tag{Key: "batch", Value: batch},
		opentracing.ChildOf(batchSpanCtx),
	)

	// Commit batch to storage.
	if err = n.commonNode.Storage.Insert(ctx, batch.MarshalCBOR(), 2, storage.InsertOptions{}); err != nil {
		spanInsert.Finish()
		n.logger.Error("failed to commit input batch to storage",
			"err", err,
		)
		return
	}
	spanInsert.Finish()

	// Dispatch batch to group.
	var batchID hash.Hash
	batchID.From(batch)

	spanPublish := opentracing.StartSpan("Publish(batchHash, header)",
		opentracing.Tag{Key: "batchHash", Value: batchID},
		opentracing.Tag{Key: "header", Value: n.commonNode.CurrentBlock.Header},
		opentracing.ChildOf(batchSpanCtx),
	)
	err = n.commonNode.Group.PublishBatch(batchSpanCtx, batchID, n.commonNode.CurrentBlock.Header)
	if err != nil {
		spanPublish.Finish()
		n.logger.Error("failed to publish batch to committee",
			"err", err,
		)
		return
	}
	crash.Here(crashPointLeaderBatchPublishAfter)
	spanPublish.Finish()

	n.transitionLocked(StateWaitingForFinalize{})

	if epoch.IsComputeLeader() || epoch.IsComputeWorker() {
		n.computeNode.HandleBatchFromTransactionSchedulerLocked(batch, batchSpanCtx)
	}

	processOk = true
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

	// Check incoming queue every MaxBatchTimeout.
	incomingQueueTicker := time.NewTicker(n.cfg.MaxBatchTimeout)
	defer incomingQueueTicker.Stop()

	// Check incoming queue when signalled.
	incomingQueueSignal := n.incomingQueue.Signal()

	// We are initialized.
	close(n.initCh)

	for {
		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case <-incomingQueueTicker.C:
			// Check incoming queue for a new batch.
			func() {
				n.commonNode.CrossNode.Lock()
				defer n.commonNode.CrossNode.Unlock()
				n.checkIncomingQueueLocked(true)
			}()
		case <-incomingQueueSignal:
			// Check incoming queue for a new batch.
			func() {
				n.commonNode.CrossNode.Lock()
				defer n.commonNode.CrossNode.Unlock()
				n.checkIncomingQueueLocked(false)
			}()
		}
	}
}

func NewNode(
	commonNode *committee.Node,
	computeNode *computeCommittee.Node,
	cfg Config,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		commonNode:       commonNode,
		computeNode:      computeNode,
		cfg:              cfg,
		ctx:              ctx,
		cancelCtx:        cancel,
		stopCh:           make(chan struct{}),
		quitCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		incomingQueue:    newIncomingQueue(cfg.MaxQueueSize, cfg.MaxBatchSize, cfg.MaxBatchSizeBytes),
		state:            StateNotReady{},
		stateTransitions: pubsub.NewBroker(false),
		logger:           logging.GetLogger("worker/txnscheduler/committee").With("runtime_id", commonNode.RuntimeID),
	}

	return n, nil
}
