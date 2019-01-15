package committee

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/common/runtime"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/host"
	"github.com/oasislabs/ekiden/go/worker/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/p2p"
)

const queueExternalBatchTimeout = 5 * time.Second

var (
	ErrNotLeader = errors.New("not leader")

	errSeenNewerBlock    = errors.New("seen newer block")
	errWorkerAborted     = errors.New("worker aborted batch processing")
	errIncomatibleHeader = errors.New("incompatible header")
	errIncorrectRole     = errors.New("incorrect role")
	errIncorrectState    = errors.New("incorrect state")
)

var (
	incomingQueueSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "ekiden_worker_incoming_queue_size",
			Help: "Size of the incoming queue (number of entries)",
		},
		[]string{"runtime"},
	)
	discrepancyDetectedCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_discrepancy_detected_count",
			Help: "Number of detected discrepancies",
		},
		[]string{"runtime"},
	)
	processedBlockCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_processed_block_count",
			Help: "Number of processed roothash blocks",
		},
		[]string{"runtime"},
	)
	failedRoundCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_failed_round_count",
			Help: "Number of failed roothash rounds",
		},
		[]string{"runtime"},
	)
	epochTransitionCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_epoch_transition_count",
			Help: "Number of epoch transitions",
		},
		[]string{"runtime"},
	)
	abortedBatchCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_worker_aborted_batch_count",
			Help: "Number of aborted batches",
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
	}

	metricsOnce sync.Once
)

// Config is a committee node configuration.
type Config struct {
	MaxQueueSize      uint64
	MaxBatchSize      uint64
	MaxBatchSizeBytes uint64
	MaxBatchTimeout   time.Duration

	ByzantineInjectDiscrepancies bool

	// XXX: This is needed until we decide how we want to actually register runtimes.
	ReplicaGroupSize       uint64
	ReplicaGroupBackupSize uint64
}

// ExternalBatch is an internal request to the worker goroutine that signals
// an external batch has been received.
type externalBatch struct {
	batch  runtime.Batch
	header block.Header
	ch     chan<- error
}

// Node is a committee node.
type Node struct {
	runtimeID signature.PublicKey

	identity   *identity.Identity
	storage    storage.Backend
	roothash   roothash.Backend
	registry   registry.Backend
	epochtime  epochtime.Backend
	scheduler  scheduler.Backend
	workerHost host.Host

	cfg Config

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopCh    chan struct{}
	stopOnce  sync.Once
	quitCh    chan struct{}
	initCh    chan struct{}

	incomingQueue    *incomingQueue
	incomingExtBatch chan *externalBatch
	group            *Group

	// No locking required, the variables in the next group are only accessed
	// and modified from the worker goroutine.
	state        NodeState
	currentBlock *block.Block

	stateTransitions *pubsub.Broker

	logger *logging.Logger
}

// Name returns the service name.
func (n *Node) Name() string {
	return "committee node"
}

// Start starts the service.
func (n *Node) Start() error {
	n.logger.Info("starting committee node")
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

// HandleBatchFromCommittee processes an incoming batch.
//
// The call has already been authenticated to come from a committee
// member.
//
// The batch identifier is a hash of the batch which can be used
// to retrieve the batch from storage.
//
// The block header determines what block the batch should be
// computed against.
func (n *Node) HandleBatchFromCommittee(ctx context.Context, batchHash hash.Hash, hdr block.Header) error {
	respCh, err := n.queueExternalBatch(ctx, batchHash, hdr)
	if err != nil {
		return err
	}

	// Wait for response from the worker goroutine.
	select {
	case resp := <-respCh:
		return resp
	case <-ctx.Done():
		return errors.New("aborted by context")
	}
}

func (n *Node) queueExternalBatch(ctx context.Context, batchHash hash.Hash, hdr block.Header) (<-chan error, error) {
	// Quick check to see if header is compatible.
	if !bytes.Equal(hdr.Namespace[:], n.runtimeID) {
		n.logger.Warn("received incompatible header in external batch",
			"header", hdr,
		)
		return nil, errIncomatibleHeader
	}

	// Fetch batch from storage.
	var k storage.Key
	copy(k[:], batchHash[:])

	raw, err := n.storage.Get(ctx, k)
	if err != nil {
		n.logger.Error("failed to fetch batch from storage",
			"err", err,
		)
		return nil, err
	}

	var batch runtime.Batch
	if err := batch.UnmarshalCBOR(raw); err != nil {
		n.logger.Error("failed to deserialize batch",
			"err", err,
		)
		return nil, err
	}

	respCh := make(chan error, 1)

	select {
	case n.incomingExtBatch <- &externalBatch{batch, hdr, respCh}:
	case <-ctx.Done():
		return nil, errors.New("aborted by context")
	}

	return respCh, nil
}

// QueueCall queues a call for processing by this node.
func (n *Node) QueueCall(ctx context.Context, call []byte) error {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.group.GetEpochSnapshot().IsLeader() {
		return ErrNotLeader
	}

	if err := n.incomingQueue.Add(call); err != nil {
		return err
	}

	incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.incomingQueue.Size()))

	return nil
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

	// Clear incoming queue if we are not a leader.
	if !epoch.IsLeader() {
		n.incomingQueue.Clear()
		incomingQueueSize.With(n.getMetricLabels()).Set(0)
	}

	if epoch.IsMember() {
		n.transition(StateWaitingForBatch{})
	} else {
		n.transition(StateNotReady{})
	}
}

func (n *Node) handleNewBlock(blk *block.Block, height int64) {
	processedBlockCount.With(n.getMetricLabels()).Inc()

	header := blk.Header

	// Update the current block.
	n.currentBlock = blk

	// If we have seen a new block while a batch was processing, we need to
	// abort it no matter what as any processed state may be invalid.
	n.abortBatch(errSeenNewerBlock)

	// Perform actions based on block type.
	switch header.HeaderType {
	case block.Normal:
		// Normal block.
		n.group.RoundTransition(n.ctx)
	case block.RoundFailed:
		// Round has failed.
		n.logger.Warn("round has failed")
		n.group.RoundTransition(n.ctx)

		failedRoundCount.With(n.getMetricLabels()).Inc()
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
	switch state := n.state.(type) {
	case StateWaitingForBlock:
		// Check if this was the block we were waiting for.
		if header.Equal(state.header) {
			n.logger.Info("received block needed for batch processing")
			n.startProcessingBatch(state.batch)
			break
		}

		// Check if the new block is for the same or newer round than the
		// one we are waiting for. In this case, we should abort as the
		// block will never be seen.
		curRound, _ := header.Round.ToU64()
		waitRound, _ := state.header.Round.ToU64()
		if curRound >= waitRound {
			n.logger.Warn("seen newer block while waiting for block")
			n.transition(StateWaitingForBatch{})
			break
		}

		// Continue waiting for block.
		n.logger.Info("still waiting for block",
			"current_round", curRound,
			"wait_round", waitRound,
		)
	case StateWaitingForFinalize:
		// A new block means the round has been finalized.
		n.logger.Info("considering the round finalized")
		n.transition(StateWaitingForBatch{})
	}
}

func (n *Node) startProcessingBatch(batch runtime.Batch) {
	if n.currentBlock == nil {
		panic("attempted to start processing batch with a nil block")
	}

	n.logger.Debug("processing batch",
		"batch", batch,
	)

	// Create batch processing context and channel for receiving the response.
	ctx, cancel := context.WithCancel(n.ctx)
	done := make(chan *protocol.ComputedBatch, 1)

	epoch := n.group.GetEpochSnapshot()
	rq := &protocol.Body{
		WorkerRuntimeCallBatchRequest: &protocol.WorkerRuntimeCallBatchRequest{
			Calls:         batch,
			Block:         *n.currentBlock,
			CommitStorage: epoch.IsLeader() || epoch.IsBackupWorker(),
		},
	}

	n.transition(StateProcessingBatch{batch, cancel, done})

	// Request the worker host to process a batch. This is done in a separate
	// goroutine so that the committee node can continue processing blocks.
	go func() {
		defer close(done)

		ch, err := n.workerHost.MakeRequest(ctx, rq)
		if err != nil {
			n.logger.Error("error while sending batch processing request to worker host",
				"err", err,
			)
			return
		}

		select {
		case response := <-ch:
			if response == nil {
				n.logger.Error("worker channel closed while processing batch")
				return
			}

			rsp := response.WorkerRuntimeCallBatchResponse
			if rsp == nil {
				n.logger.Error("malformed response from worker",
					"response", response,
				)
				return
			}

			done <- &rsp.Batch
		case <-ctx.Done():
			n.logger.Error("batch processing aborted by context, interrupting worker")

			// Interrupt the worker, so we can start processing the next batch.
			err := n.workerHost.InterruptWorker(n.ctx)
			if err != nil {
				n.logger.Error("failed to interrupt the worker",
					"err", err,
				)
			}
			return
		}
	}()
}

func (n *Node) abortBatch(reason error) {
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

	// If we are a leader, put the batch back into the incoming queue.
	if n.group.GetEpochSnapshot().IsLeader() {
		if err := n.incomingQueue.AddBatch(state.batch); err != nil {
			n.logger.Warn("failed to add batch back into the incoming queue",
				"err", err,
			)
		}

		incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.incomingQueue.Size()))
	}

	abortedBatchCount.With(n.getMetricLabels()).Inc()

	// After the batch has been aborted, we must wait for the round to be
	// finalized.
	n.transition(StateWaitingForFinalize{})
}

func (n *Node) proposeBatch(batch *protocol.ComputedBatch) {
	n.logger.Debug("proposing batch",
		"batch", batch,
	)

	epoch := n.group.GetEpochSnapshot()

	// Byzantine mode: inject discrepancy.
	if n.cfg.ByzantineInjectDiscrepancies {
		n.logger.Error("BYZANTINE MODE: injecting discrepancy into batch")

		for idx := range batch.Outputs {
			batch.Outputs[idx] = []byte("boom")
		}
	}

	// Generate proposed block header.
	blk := block.NewEmptyBlock(n.currentBlock, 0, block.Normal)
	blk.Header.GroupHash = epoch.GetGroupHash()
	blk.Header.InputHash.From(batch.Calls)
	blk.Header.OutputHash.From(batch.Outputs)
	blk.Header.StateRoot = batch.NewStateRoot

	// Commit outputs to storage.
	if epoch.IsLeader() || epoch.IsBackupWorker() {
		if err := n.storage.Insert(n.ctx, batch.Outputs.MarshalCBOR(), 2); err != nil {
			n.logger.Error("failed to commit outputs to storage",
				"err", err,
			)
			n.abortBatch(err)
			return
		}
	}

	// Commit header.
	commit, err := commitment.SignCommitment(*n.identity.NodeKey, &blk.Header)
	if err != nil {
		n.logger.Error("failed to sign commitment",
			"err", err,
		)
		n.abortBatch(err)
		return
	}

	n.transition(StateWaitingForFinalize{})

	if err := n.roothash.Commit(n.ctx, n.runtimeID, commit.ToOpaqueCommitment()); err != nil {
		n.logger.Error("failed to submit commitment",
			"err", err,
		)
		n.abortBatch(err)
		return
	}
}

func (n *Node) handleNewEvent(ev *roothash.Event) {
	dis := ev.DiscrepancyDetected
	if dis == nil {
		panic(fmt.Sprintf("unsupported event type: %+v", ev))
	}

	n.logger.Warn("discrepancy detected",
		"input_hash", dis.BatchHash,
		"header", dis.BlockHeader,
	)

	discrepancyDetectedCount.With(n.getMetricLabels()).Inc()

	if n.group.GetEpochSnapshot().IsBackupWorker() {
		// Backup worker, start processing a batch.
		n.logger.Info("backup worker activating and processing batch",
			"input_hash", dis.BatchHash,
			"header", dis.BlockHeader,
		)

		// This may block if we are unable to fetch the batch from storage or if
		// the external batch channel is full. Be sure to abort early in this case.
		ctx, cancel := context.WithTimeout(n.ctx, queueExternalBatchTimeout)
		defer cancel()

		if _, err := n.queueExternalBatch(ctx, *dis.BatchHash, *dis.BlockHeader); err != nil {
			n.logger.Error("backup worker failed to queue external batch",
				"err", err,
			)
		}
	}
}

func (n *Node) checkIncomingQueue(force bool) {
	// If we are not waiting for a batch, don't do anything.
	if _, ok := n.state.(StateWaitingForBatch); !ok {
		return
	}

	// If we are not a leader or we don't have any blocks, don't do anything.
	if !n.group.GetEpochSnapshot().IsLeader() || n.currentBlock == nil {
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
			if err := n.incomingQueue.AddBatch(batch); err != nil {
				n.logger.Error("failed to add batch back into the incoming queue",
					"err", err,
				)
			}
		}

		incomingQueueSize.With(n.getMetricLabels()).Set(float64(n.incomingQueue.Size()))
	}()

	// Commit batch to storage.
	if err := n.storage.Insert(n.ctx, batch.MarshalCBOR(), 2); err != nil {
		n.logger.Error("failed to commit input batch to storage",
			"err", err,
		)
		return
	}

	// Dispatch batch to group.
	var batchID hash.Hash
	batchID.From(batch)

	if err := n.group.PublishBatch(batchID, n.currentBlock.Header); err != nil {
		n.logger.Error("failed to publish batch to committee",
			"err", err,
		)
		return
	}

	// Start processing the batch locally.
	n.startProcessingBatch(batch)

	processOk = true
}

func (n *Node) handleExternalBatch(batch *externalBatch) error {
	// If we are not waiting for a batch, don't do anything.
	if _, ok := n.state.(StateWaitingForBatch); !ok {
		return errIncorrectState
	}

	epoch := n.group.GetEpochSnapshot()

	// We can only receive external batches if we are a worker or a backup worker.
	if !epoch.IsWorker() && !epoch.IsBackupWorker() {
		n.logger.Error("got external batch while in incorrect role")
		return errIncorrectRole
	}

	// Check if we have the correct block -- in this case, start processing the batch.
	if n.currentBlock.Header.Equal(&batch.header) {
		n.startProcessingBatch(batch.batch)
		return nil
	}

	// Check if the current block is older than what is expected we base our batch
	// on. In case it is equal or newer, but different, discard the batch.
	curRound, _ := n.currentBlock.Header.Round.ToU64()
	waitRound, _ := batch.header.Round.ToU64()
	if curRound >= waitRound {
		n.logger.Warn("got external batch based on incompatible header",
			"header", batch.header,
		)
		return errIncomatibleHeader
	}

	// Wait for the correct block to arrive.
	n.transition(StateWaitingForBlock{batch.batch, &batch.header})

	return nil
}

func (n *Node) worker() {
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

	// Start watching roothash events.
	events, eventsSub, err := n.roothash.WatchEvents(n.runtimeID)
	if err != nil {
		n.logger.Error("failed to subscribe to roothash events",
			"err", err,
		)
		return
	}
	defer eventsSub.Close()

	// Check incoming queue every MaxBatchTimeout.
	incomingQueueTicker := time.NewTicker(n.cfg.MaxBatchTimeout)
	defer incomingQueueTicker.Stop()

	// Check incoming queue when signalled.
	incomingQueueSignal := n.incomingQueue.Signal()

	// We are initialized.
	close(n.initCh)

	for {
		// Check if we are currently processing a batch. In this case, we also
		// need to select over the result channel.
		var processingDoneCh chan *protocol.ComputedBatch
		if stateProcessing, ok := n.state.(StateProcessingBatch); ok {
			processingDoneCh = stateProcessing.done
		}

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
		case batch := <-processingDoneCh:
			// Batch processing has finished.
			if batch == nil {
				n.logger.Warn("worker has aborted batch processing")
				n.abortBatch(errWorkerAborted)
				break
			}

			n.logger.Info("worker has finished processing a batch")

			n.proposeBatch(batch)
		case ev := <-events:
			// Received an event.
			n.handleNewEvent(ev)
		case <-incomingQueueTicker.C:
			// Check incoming queue for a new batch.
			n.checkIncomingQueue(true)
		case <-incomingQueueSignal:
			// Check incoming queue for a new batch.
			n.checkIncomingQueue(false)
		case batch := <-n.incomingExtBatch:
			// New incoming batch from an external source (compute committee or
			// roothash discrepancy event).
			err := n.handleExternalBatch(batch)
			batch.ch <- err
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
	worker host.Host,
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
		workerHost:       worker,
		cfg:              cfg,
		ctx:              ctx,
		cancelCtx:        cancel,
		quitCh:           make(chan struct{}),
		stopCh:           make(chan struct{}),
		initCh:           make(chan struct{}),
		incomingQueue:    newIncomingQueue(cfg.MaxQueueSize, cfg.MaxBatchSize, cfg.MaxBatchSizeBytes),
		incomingExtBatch: make(chan *externalBatch, 10),
		state:            StateNotReady{},
		stateTransitions: pubsub.NewBroker(false),
		logger:           logging.GetLogger("worker/committee").With("runtime_id", runtimeID),
	}
	group, err := NewGroup(identity, runtimeID, n, registry, scheduler, p2p)
	if err != nil {
		return nil, err
	}
	n.group = group

	return n, nil
}
