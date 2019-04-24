package committee

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/opentracing/opentracing-go"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/identity"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/common/runtime"
	"github.com/oasislabs/ekiden/go/common/tracing"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/worker/common/host"
	"github.com/oasislabs/ekiden/go/worker/common/host/protocol"
	"github.com/oasislabs/ekiden/go/worker/compute/p2p"
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
	storageCommitLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_worker_storage_commit_latency",
			Help: "Latency of storage commit calls (state + outputs)",
		},
		[]string{"runtime"},
	)
	batchProcessingTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_worker_batch_processing_time",
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

	ByzantineInjectDiscrepancies bool
}

// ExternalBatch is an internal request to the worker goroutine that signals
// an external batch has been received.
type externalBatch struct {
	batch   runtime.Batch
	header  block.Header
	ch      chan<- error
	spanCtx opentracing.SpanContext
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
	consensus  common.ConsensusBackend

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
		return context.Canceled
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

	var batchSpanCtx opentracing.SpanContext
	if batchSpan := opentracing.SpanFromContext(ctx); batchSpan != nil {
		batchSpanCtx = batchSpan.Context()
	}
	span, ctx := tracing.StartSpanWithContext(ctx, "Get(batchHash)",
		opentracing.Tag{Key: "batchHash", Value: k},
		opentracing.ChildOf(batchSpanCtx),
	)
	raw, err := n.storage.Get(ctx, k)
	span.Finish()
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
	case n.incomingExtBatch <- &externalBatch{batch, hdr, respCh, batchSpanCtx}:
	case <-ctx.Done():
		return nil, context.Canceled
	}

	return respCh, nil
}

// QueueCall queues a call for processing by this node.
func (n *Node) QueueCall(ctx context.Context, call []byte) error {
	// Check if we are a leader. Note that we may be in the middle of a
	// transition, but this shouldn't matter as the client will retry.
	if !n.group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
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
	if !n.group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
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

	// Clear incoming queue if we are not a leader.
	if !epoch.IsTransactionSchedulerLeader() {
		n.incomingQueue.Clear()
		incomingQueueSize.With(n.getMetricLabels()).Set(0)
	}

	if epoch.IsComputeMember() {
		n.transition(StateWaitingForBatch{})
	} else {
		n.transition(StateNotReady{})
	}
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

	// If we have seen a new block while a batch was processing, we need to
	// abort it no matter what as any processed state may be invalid.
	n.abortBatch(errSeenNewerBlock)

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
	switch state := n.state.(type) {
	case StateWaitingForBlock:
		// Check if this was the block we were waiting for.
		if header.MostlyEqual(state.header) {
			n.logger.Info("received block needed for batch processing")
			n.startProcessingBatch(state.batch)
			break
		}

		// Check if the new block is for the same or newer round than the
		// one we are waiting for. In this case, we should abort as the
		// block will never be seen.
		curRound := header.Round
		waitRound := state.header.Round
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

		// Record time taken for successfully processing a batch.
		batchProcessingTime.With(n.getMetricLabels()).Observe(time.Since(n.batchStartTime).Seconds())
		n.batchStartTime = time.Time{}
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

	rq := &protocol.Body{
		WorkerExecuteTxBatchRequest: &protocol.WorkerExecuteTxBatchRequest{
			Calls: batch,
			Block: *n.currentBlock,
		},
	}

	n.batchStartTime = time.Now()

	n.transition(StateProcessingBatch{batch, cancel, done})

	// Request the worker host to process a batch. This is done in a separate
	// goroutine so that the committee node can continue processing blocks.
	go func() {
		defer close(done)

		span := opentracing.StartSpan("CallBatch(rq)",
			opentracing.Tag{Key: "rq", Value: rq},
			opentracing.ChildOf(n.batchSpanCtx),
		)
		ctx = opentracing.ContextWithSpan(ctx, span)
		defer span.Finish()

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

			rsp := response.WorkerExecuteTxBatchResponse
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
			err = n.workerHost.InterruptWorker(n.ctx)
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
	if n.group.GetEpochSnapshot().IsTransactionSchedulerLeader() {
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
	// We must be in ProcessingBatch state if we are here.
	state := n.state.(StateProcessingBatch)

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
	blk.Header.InputHash.From(state.batch)
	blk.Header.OutputHash.From(batch.Outputs)
	blk.Header.TagHash.From(batch.Tags)
	blk.Header.StateRoot = batch.NewStateRoot

	// Commit outputs and state to storage. If we are a regular worker, then we only
	// insert into local cache.
	var opts storage.InsertOptions
	if !epoch.IsComputeLeader() && !epoch.IsComputeBackupWorker() {
		opts.LocalOnly = true
	}

	start := time.Now()
	err := func() error {
		span, ctx := tracing.StartSpanWithContext(n.ctx, "InsertBatch(outputs, state, tags)",
			opentracing.ChildOf(n.batchSpanCtx),
		)
		defer span.Finish()

		ctx, cancel := context.WithTimeout(ctx, n.cfg.StorageCommitTimeout)
		defer cancel()

		batch.StorageInserts = append(batch.StorageInserts, storage.Value{
			Data:       batch.Outputs.MarshalCBOR(),
			Expiration: 2,
		}, storage.Value{
			Data:       cbor.Marshal(batch.Tags),
			Expiration: 2,
		})
		if err := n.storage.InsertBatch(ctx, batch.StorageInserts, opts); err != nil {
			n.logger.Error("failed to commit state to storage",
				"err", err,
			)
			return err
		}

		if opts.LocalOnly {
			return nil
		}

		// If we actually write to storage, acquire proof that we did.
		signedReceipt, err := n.storage.GetReceipt(ctx, blk.Header.KeysForStorageReceipt())
		if err != nil {
			n.logger.Error("failed to get storage proof",
				"err", err,
			)
			return err
		}

		// TODO: Ensure that the receipt is actually signed by the
		// storage node.  For now accept a signature from anyone.
		var receipt storage.Receipt
		if err = signedReceipt.Open(storage.ReceiptSignatureContext, &receipt); err != nil {
			n.logger.Error("failed to open signed receipt",
				"err", err,
			)
			return err
		}
		if err = blk.Header.VerifyStorageReceipt(&receipt); err != nil {
			n.logger.Error("failed to validate receipt",
				"err", err,
			)
			return err
		}

		// No need to append the entire blob, just the signature/public key.
		blk.Header.StorageReceipt = signedReceipt.Signature

		return nil
	}()
	storageCommitLatency.With(n.getMetricLabels()).Observe(time.Since(start).Seconds())

	if err != nil {
		n.abortBatch(err)
		return
	}

	// Commit.
	commit, err := commitment.SignCommitment(*n.identity.NodeKey, &commitment.Message{
		Header: blk.Header,
		RakSig: batch.RakSig,
	})
	if err != nil {
		n.logger.Error("failed to sign commitment",
			"err", err,
		)
		n.abortBatch(err)
		return
	}

	n.transition(StateWaitingForFinalize{})

	span := opentracing.StartSpan("roothash.Commit", opentracing.ChildOf(n.batchSpanCtx))
	defer span.Finish()

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

	if n.group.GetEpochSnapshot().IsComputeBackupWorker() {
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

	epochSnapshot := n.group.GetEpochSnapshot()
	// If we are not a leader or we don't have any blocks, don't do anything.
	if !epochSnapshot.IsTransactionSchedulerLeader() || n.currentBlock == nil {
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
	if err := n.storage.Insert(ctx, batch.MarshalCBOR(), 2, storage.InsertOptions{}); err != nil {
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
	if err := n.group.PublishBatch(n.batchSpanCtx, batchID, n.currentBlock.Header); err != nil {
		spanPublish.Finish()
		n.logger.Error("failed to publish batch to committee",
			"err", err,
		)
		return
	}
	spanPublish.Finish()

	if epochSnapshot.IsComputeLeader() || epochSnapshot.IsComputeWorker() {
		// Start processing the batch locally.
		n.startProcessingBatch(batch)
	}

	processOk = true
}

func (n *Node) handleExternalBatch(batch *externalBatch) error {
	// If we are not waiting for a batch, don't do anything.
	if _, ok := n.state.(StateWaitingForBatch); !ok {
		return errIncorrectState
	}

	epoch := n.group.GetEpochSnapshot()

	// We can only receive external batches if we are a compute member.
	if !epoch.IsComputeMember() {
		n.logger.Error("got external batch while in incorrect role")
		return errIncorrectRole
	}

	// Set the Worker node's batchSpan from the obtained external batch.
	n.batchSpanCtx = batch.spanCtx

	// Check if we have the correct block -- in this case, start processing the batch.
	if n.currentBlock.Header.MostlyEqual(&batch.header) {
		n.startProcessingBatch(batch.batch)
		return nil
	}

	// Check if the current block is older than what is expected we base our batch
	// on. In case it is equal or newer, but different, discard the batch.
	curRound := n.currentBlock.Header.Round
	waitRound := batch.header.Round
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
	// Delay starting of committee node until after the consensus service
	// has finished initial synchronization, if applicable.
	if n.consensus != nil {
		n.logger.Info("delaying committee node start until after initial synchronization")
		select {
		case <-n.quitCh:
			return
		case <-n.consensus.Synced():
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
	consensus common.ConsensusBackend,
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
		consensus:        consensus,
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
		logger:           logging.GetLogger("worker/compute/committee").With("runtime_id", runtimeID),
	}
	group, err := NewGroup(identity, runtimeID, n, registry, scheduler, p2p)
	if err != nil {
		return nil, err
	}
	n.group = group

	return n, nil
}
