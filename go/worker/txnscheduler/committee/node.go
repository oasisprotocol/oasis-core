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

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/common/tracing"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	computeCommittee "github.com/oasislabs/ekiden/go/worker/compute/committee"
	"github.com/oasislabs/ekiden/go/worker/p2p"
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
	discrepancyDetectedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_txnscheduler_discrepancy_detected_count",
			Help: "Number of detected discrepancies",
		},
		[]string{"runtime"},
	)
	processedBlockCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_txnscheduler_processed_block_count",
			Help: "Number of processed roothash blocks",
		},
		[]string{"runtime"},
	)
	failedRoundCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_txnscheduler_failed_round_count",
			Help: "Number of failed roothash rounds",
		},
		[]string{"runtime"},
	)
	epochTransitionCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_txnscheduler_epoch_transition_count",
			Help: "Number of epoch transitions",
		},
		[]string{"runtime"},
	)
	abortedBatchCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_txnscheduler_aborted_batch_count",
			Help: "Number of aborted batches",
		},
		[]string{"runtime"},
	)
	storageCommitLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_worker_txnscheduler_storage_commit_latency",
			Help: "Latency of storage commit calls (state + outputs)",
		},
		[]string{"runtime"},
	)
	batchProcessingTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_worker_txnscheduler_batch_processing_time",
			Help: "Time it takes for a batch to finalize",
		},
		[]string{"runtime"},
	)
	nodeCollectors = []prometheus.Collector{
		incomingQueueSize,
		discrepancyDetectedCount,
		processedBlockCount,
		failedRoundCount,
		epochTransitionCount,
		abortedBatchCount,
		storageCommitLatency,
		batchProcessingTime,
	}

	metricsOnce sync.Once
)

// Config is a committee node configuration.
type Config struct {
	MaxQueueSize      uint64
	MaxBatchSize      uint64
	MaxBatchSizeBytes uint64
	MaxBatchTimeout   time.Duration

	StorageCommitTimeout time.Duration
}

// Node is a committee node.
type Node struct {
	runtimeID signature.PublicKey

	identity    *identity.Identity
	storage     storage.Backend
	roothash    roothash.Backend
	registry    registry.Backend
	epochtime   epochtime.Backend
	scheduler   scheduler.Backend
	syncable    common.Syncable
	computeNode *computeCommittee.Node

	cfg Config

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	stopOnce  sync.Once
	quitCh    chan struct{}
	initCh    chan struct{}

	incomingQueue *incomingQueue
	group         *Group

	// No locking required, the variables in the next group are only accessed
	// and modified from the worker goroutine.
	state          NodeState
	currentBlock   *block.Block
	batchStartTime time.Time
	batchSpanCtx   opentracing.SpanContext

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
		"runtime": n.runtimeID.String(),
	}
}

// QueueCall queues a call for processing by this node.
func (n *Node) QueueCall(ctx context.Context, call []byte) error {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.group.GetEpochSnapshot().IsLeader() {
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
	if !n.group.GetEpochSnapshot().IsLeader() {
		return false, ErrNotLeader
	}

	return n.incomingQueue.IsQueued(id), nil
}

func (n *Node) transition(state NodeState) {
	n.logger.Info("state transition",
		"current_state", n.state,
		"new_state", state,
	)

	// Validate state transition.
	dests := validStateTransitions[n.state.String()]

	var valid bool
	for _, dest := range dests[:] {
		if dest == state.String() {
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

func (n *Node) handleEpochTransition(groupHash hash.Hash, height int64) {
	n.logger.Info("epoch transition has occurred",
		"new_group_hash", groupHash,
	)

	epochTransitionCount.With(n.getMetricLabels()).Inc()

	// Transition group.
	if err := n.group.EpochTransition(n.ctx, groupHash, height); err != nil {
		n.logger.Error("unable to handle epoch transition",
			"err", err,
		)
	}

	epoch := n.group.GetEpochSnapshot()

	if epoch.IsLeader() {
		n.transition(StateWaitingForBatch{})
	} else {
		n.incomingQueue.Clear()
		// Clear incoming queue if we are not a leader.
		incomingQueueSize.With(n.getMetricLabels()).Set(0)
		n.transition(StateNotReady{})
	}
	// TODO: Make non-leader members follow.
}

func (n *Node) handleNewBlock(blk *block.Block, height int64) {
	processedBlockCount.With(n.getMetricLabels()).Inc()

	header := blk.Header

	// The first received block will be treated an epoch transition (if valid).
	// This will refresh the committee on the first block,
	// instead of waiting for the next epoch transition to occur.
	// Helps in cases where node is restarted mid epoch.
	firstBlockReceived := n.currentBlock == nil

	// Update the current block.
	n.currentBlock = blk

	// Perform actions based on block type.
	switch header.HeaderType {
	case block.Normal:
		if firstBlockReceived {
			n.logger.Warn("forcing an epoch transition on first received block")
			n.handleEpochTransition(header.GroupHash, height)
		} else {
			// Normal block.
			n.group.RoundTransition(n.ctx)
		}
	case block.RoundFailed:
		if firstBlockReceived {
			n.logger.Warn("forcing an epoch transition on first received block")
			n.handleEpochTransition(header.GroupHash, height)
		} else {
			// Round has failed.
			n.logger.Warn("round has failed")
			n.group.RoundTransition(n.ctx)

			failedRoundCount.With(n.getMetricLabels()).Inc()
		}
	case block.EpochTransition:
		// Process an epoch transition.
		n.handleEpochTransition(header.GroupHash, height)
	default:
		n.logger.Error("invalid block type",
			"block", blk,
		)
		return
	}

	// Perform actions based on current state.
	switch n.state.(type) {
	case StateWaitingForFinalize:
		// A new block means the round has been finalized.
		n.logger.Info("considering the round finalized")
		n.transition(StateWaitingForBatch{})

		// Record time taken for successfully processing a batch.
		batchProcessingTime.With(n.getMetricLabels()).Observe(time.Since(n.batchStartTime).Seconds())
		n.batchStartTime = time.Time{}
	}
}

func (n *Node) batchSent() {
	n.batchStartTime = time.Now()

	n.transition(StateWaitingForFinalize{})
}

func (n *Node) checkIncomingQueue(force bool) {
	// If we are not waiting for a batch, don't do anything.
	if _, ok := n.state.(StateWaitingForBatch); !ok {
		return
	}

	epochSnapshot := n.group.GetEpochSnapshot()
	// If we are not a leader or we don't have any blocks, don't do anything.
	if !epochSnapshot.IsLeader() || n.currentBlock == nil {
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
	n.batchSpanCtx = batchSpan.Context()

	spanInsert, ctx := tracing.StartSpanWithContext(n.ctx, "Insert(batch)",
		opentracing.Tag{Key: "batch", Value: batch},
		opentracing.ChildOf(n.batchSpanCtx),
	)

	// Commit batch to storage.
	if err = n.storage.Insert(ctx, batch.MarshalCBOR(), 2, storage.InsertOptions{}); err != nil {
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
		opentracing.Tag{Key: "header", Value: n.currentBlock.Header},
		opentracing.ChildOf(n.batchSpanCtx),
	)
	publishToSelf, err := n.group.PublishBatch(n.batchSpanCtx, batchID, n.currentBlock.Header)
	if err != nil {
		spanPublish.Finish()
		n.logger.Error("failed to publish batch to committee",
			"err", err,
		)
		return
	}
	spanPublish.Finish()

	n.batchSent()

	if publishToSelf {
		n.computeNode.HandleBatchFromTransactionScheduler(batch, n.currentBlock.Header)
	}

	processOk = true
}

func (n *Node) worker() {
	// Delay starting of committee node until after the consensus service
	// has finished initial synchronization, if applicable.
	if n.syncable != nil {
		n.logger.Info("delaying committee node start until after initial synchronization")
		select {
		case <-n.quitCh:
			return
		case <-n.syncable.Synced():
		}
	}
	n.logger.Info("starting committee node")

	defer close(n.quitCh)
	defer (n.cancelCtx)()

	// Start watching roothash blocks.
	var blocksAnn <-chan *roothash.AnnotatedBlock
	var blocksPlain <-chan *block.Block
	var blocksSub *pubsub.Subscription
	var err error
	if rh, ok := n.roothash.(roothash.BlockBackend); ok {
		blocksAnn, blocksSub, err = rh.WatchAnnotatedBlocks(n.runtimeID)
	} else {
		blocksPlain, blocksSub, err = n.roothash.WatchBlocks(n.runtimeID)
	}
	if err != nil {
		n.logger.Error("failed to subscribe to roothash blocks",
			"err", err,
		)
		return
	}
	defer blocksSub.Close()

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
		case blk := <-blocksAnn:
			// Received a block (annotated).
			n.handleNewBlock(blk.Block, blk.Height)
		case blk := <-blocksPlain:
			// Received a block (plain).
			n.handleNewBlock(blk, 0)
		case <-incomingQueueTicker.C:
			// Check incoming queue for a new batch.
			n.checkIncomingQueue(true)
		case <-incomingQueueSignal:
			// Check incoming queue for a new batch.
			n.checkIncomingQueue(false)
		}
	}
}

func NewNode(
	runtimeID signature.PublicKey,
	identity *identity.Identity,
	storage storage.Backend,
	roothash roothash.Backend,
	registry registry.Backend,
	epochtime epochtime.Backend,
	scheduler scheduler.Backend,
	syncable common.Syncable,
	computeNode *computeCommittee.Node,
	p2p *p2p.P2P,
	cfg Config,
) (*Node, error) {
	metricsOnce.Do(func() {
		prometheus.MustRegister(nodeCollectors...)
	})

	ctx, cancel := context.WithCancel(context.Background())

	n := &Node{
		runtimeID:        runtimeID,
		identity:         identity,
		storage:          storage,
		roothash:         roothash,
		registry:         registry,
		epochtime:        epochtime,
		scheduler:        scheduler,
		syncable:         syncable,
		computeNode:      computeNode,
		cfg:              cfg,
		ctx:              ctx,
		cancelCtx:        cancel,
		quitCh:           make(chan struct{}),
		stopCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		incomingQueue:    newIncomingQueue(cfg.MaxQueueSize, cfg.MaxBatchSize, cfg.MaxBatchSizeBytes),
		state:            StateNotReady{},
		stateTransitions: pubsub.NewBroker(false),
		logger:           logging.GetLogger("worker/txnclient/committee").With("runtime_id", runtimeID),
	}
	group, err := NewGroup(identity, runtimeID, registry, scheduler, p2p)
	if err != nil {
		return nil, err
	}
	n.group = group

	return n, nil
}
