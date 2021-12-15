package txpool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eapache/channels"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling"
	schedulingAPI "github.com/oasisprotocol/oasis-core/go/runtime/scheduling/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// Config is the transaction pool configuration.
type Config struct {
	MaxPoolSize          uint64
	MaxCheckTxBatchSize  uint64
	MaxLastSeenCacheSize uint64

	RepublishInterval     time.Duration
	MaxRepublishBatchSize uint64
}

// TransactionMeta contains the per-transaction metadata.
type TransactionMeta struct {
	// Local is a flag denoting the transaction as obtained from a local client.
	Local bool
}

// TransactionPool is an interface for managing a pool of transactions.
type TransactionPool interface {
	// Start starts the service.
	Start() error

	// Stop halts the service.
	Stop()

	// Quit returns a channel that will be closed when the service terminates.
	Quit() <-chan struct{}

	// Submit adds the transaction into the transaction pool, first performing checks on it by
	// invoking the runtime. This method waits for the checks to complete.
	SubmitTx(ctx context.Context, tx []byte, meta *TransactionMeta) error

	// SubmitTxNoWait adds the transaction into the transaction pool and returns immediately.
	SubmitTxNoWait(ctx context.Context, tx []byte, meta *TransactionMeta) error

	// ProcessBlock updates the last known runtime block information.
	ProcessBlock(bi *BlockInfo) error

	// UpdateWeightLimits updates the per-batch weight limits.
	UpdateWeightLimits(limits map[transaction.Weight]uint64) error

	// WakeupScheduler explicitly notifies subscribers that they should attempt scheduling.
	WakeupScheduler()

	// Clear clears the transaction pool.
	Clear()

	// Scheduler returns the scheduler used for scheduling transactions for this pool.
	Scheduler() schedulingAPI.Scheduler

	// WatchScheduler subscribes to notifications about when to attempt scheduling. The emitted
	// boolean flag indicates whether the batch flush timeout expired.
	WatchScheduler() (pubsub.ClosableSubscription, <-chan bool)

	// WatchCheckedTransactions subscribes to notifications about new transactions being available
	// in the transaction pool for scheduling.
	WatchCheckedTransactions() (pubsub.ClosableSubscription, <-chan []*transaction.CheckedTransaction)
}

// TODO: consider moving this interface to runtime/host.
// RuntimeHostProvisioner is a runtime host provisioner.
type RuntimeHostProvisioner interface {
	WaitHostedRuntime(ctx context.Context) (host.RichRuntime, error)
}

// TransactionPublisher is an interface representing a mechanism for publishing transactions.
type TransactionPublisher interface {
	// PublishTx publishes a transaction to remote peers.
	PublishTx(ctx context.Context, tx []byte) error

	// GetMinRepublishInterval returns the minimum republish interval that needs to be respected by
	// the caller. If PublishTx is called for the same transaction more quickly, the transaction
	// may be dropped and not published.
	GetMinRepublishInterval() time.Duration
}

// TODO: Consider moving.
// BlockInfo contains information related to the given runtime block.
type BlockInfo struct {
	// RuntimeBlock is the runtime block.
	RuntimeBlock *block.Block

	// ConsensusBlock is the consensus light block the runtime block belongs to.
	ConsensusBlock *consensus.LightBlock

	// Epoch is the epoch the runtime block belongs to.
	Epoch beacon.EpochTime

	// ActiveDescriptor is the runtime descriptor active for the runtime block.
	ActiveDescriptor *registry.Runtime
}

type txPool struct {
	logger *logging.Logger

	stopCh chan struct{}
	quitCh chan struct{}
	initCh chan struct{}

	cfg         *Config
	host        RuntimeHostProvisioner
	txPublisher TransactionPublisher

	// seenCache maps from transaction hashes to time.Time that specifies when the transaction was
	// last published.
	seenCache *lru.Cache

	checkTxCh       *channels.RingChannel
	checkTxQueue    *checkTxQueue
	checkTxNotifier *pubsub.Broker

	schedulerLock     sync.Mutex
	scheduler         schedulingAPI.Scheduler
	schedulerTicker   *time.Ticker
	schedulerNotifier *pubsub.Broker

	blockInfoLock sync.Mutex
	blockInfo     *BlockInfo

	// roundWeightLimits is guarded by schedulerLock.
	roundWeightLimits map[transaction.Weight]uint64
}

func (t *txPool) Start() error {
	go t.checkWorker()
	go t.republishWorker()
	go t.flushWorker()
	return nil
}

func (t *txPool) Stop() {
	close(t.stopCh)
}

func (t *txPool) Quit() <-chan struct{} {
	return t.quitCh
}

func (t *txPool) SubmitTx(ctx context.Context, rawTx []byte, meta *TransactionMeta) error {
	notifyCh := make(chan *protocol.CheckTxResult, 1)
	err := t.submitTx(ctx, rawTx, meta, notifyCh)
	if err != nil {
		close(notifyCh)
		return err
	}

	// Wait for response from transaction checks.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.stopCh:
		return fmt.Errorf("shutting down")
	case result := <-notifyCh:
		if !result.IsSuccess() {
			return errors.New(result.Error.String())
		}
		return nil
	}
}

func (t *txPool) SubmitTxNoWait(ctx context.Context, tx []byte, meta *TransactionMeta) error {
	return t.submitTx(ctx, tx, meta, nil)
}

func (t *txPool) submitTx(ctx context.Context, rawTx []byte, meta *TransactionMeta, notifyCh chan *protocol.CheckTxResult) error {
	// Skip recently seen transactions.
	txHash := hash.NewFromBytes(rawTx)
	if _, seen := t.seenCache.Get(txHash); seen {
		t.logger.Debug("ignoring already seen transaction", "tx", rawTx)
		return nil
	}

	tx := &pendingTx{
		Tx:       rawTx,
		TxHash:   txHash,
		Meta:     meta,
		NotifyCh: notifyCh,
	}

	// Queue transaction for checks.
	t.logger.Debug("queuing transaction for check",
		"tx", rawTx,
	)
	if err := t.checkTxQueue.Add(tx); err != nil {
		t.logger.Warn("unable to queue transaction",
			"tx", rawTx,
			"err", err,
		)
		return err
	}

	// Wake up the check batcher.
	t.checkTxCh.In() <- struct{}{}

	return nil
}

func (t *txPool) ProcessBlock(bi *BlockInfo) error {
	t.blockInfoLock.Lock()
	defer t.blockInfoLock.Unlock()

	if t.blockInfo == nil || bi.RuntimeBlock.Header.HeaderType == block.EpochTransition {
		// Handle scheduler updates.
		if err := t.updateScheduler(bi); err != nil {
			return fmt.Errorf("failed to update scheduler: %w", err)
		}
	}

	t.blockInfo = bi

	return nil
}

func (t *txPool) updateScheduler(bi *BlockInfo) error {
	t.schedulerLock.Lock()
	defer t.schedulerLock.Unlock()

	// Update per round weight limits.
	t.roundWeightLimits[transaction.WeightConsensusMessages] = uint64(bi.ActiveDescriptor.Executor.MaxMessages)
	t.roundWeightLimits[transaction.WeightSizeBytes] = bi.ActiveDescriptor.TxnScheduler.MaxBatchSizeBytes
	t.roundWeightLimits[transaction.WeightCount] = bi.ActiveDescriptor.TxnScheduler.MaxBatchSize

	switch t.scheduler {
	case nil:
		// We still need to initialize the scheduler.
		t.logger.Debug("initializing transaction scheduler",
			"algorithm", bi.ActiveDescriptor.TxnScheduler.Algorithm,
		)

		sched, err := scheduling.New(t.cfg.MaxPoolSize, bi.ActiveDescriptor.TxnScheduler.Algorithm, t.roundWeightLimits)
		if err != nil {
			return fmt.Errorf("failed to create transaction scheduler: %w", err)
		}

		t.scheduler = sched
		close(t.initCh)
	default:
		// Scheduler already initialized.

		// NOTE: Once there are multiple scheduling algorithms, this should handle the case of the
		//       algorithm itself being updated (and the scheduler being recreated).
		if bi.ActiveDescriptor.TxnScheduler.Algorithm != t.scheduler.Name() {
			t.logger.Error("attempted to update transaction scheduler algorithm",
				"current", t.scheduler.Name(),
				"new", bi.ActiveDescriptor.TxnScheduler.Algorithm,
			)
			return fmt.Errorf("transaction scheduler algorithm update not supported")
		}

		// TODO: Remove the extra scheduler algorithm parameter.
		if err := t.scheduler.UpdateParameters(t.scheduler.Name(), t.roundWeightLimits); err != nil {
			t.logger.Error("error updating transaction scheduler parameters",
				"err", err,
			)
			return fmt.Errorf("failed to update transaction scheduler parameters: %w", err)
		}
	}

	// Reset ticker to the new interval.
	t.schedulerTicker.Reset(bi.ActiveDescriptor.TxnScheduler.BatchFlushTimeout)

	return nil
}

func (t *txPool) UpdateWeightLimits(limits map[transaction.Weight]uint64) error {
	t.schedulerLock.Lock()
	defer t.schedulerLock.Unlock()

	// Remove batch custom weight limits that don't exist anymore.
	for w := range t.roundWeightLimits {
		// Skip non custom runtime weights.
		if !w.IsCustom() {
			continue
		}

		if _, exists := limits[w]; !exists {
			delete(t.roundWeightLimits, w)
		}
	}
	// Update batch weight limits.
	for w, l := range limits {
		t.roundWeightLimits[w] = l
	}

	if err := t.scheduler.UpdateParameters(t.scheduler.Name(), t.roundWeightLimits); err != nil {
		return fmt.Errorf("updating scheduler parameters: %w", err)
	}

	t.logger.Debug("updated round batch weight limits",
		"weight_limits", t.roundWeightLimits,
	)

	return nil
}

func (t *txPool) WakeupScheduler() {
	t.schedulerNotifier.Broadcast(false)
}

func (t *txPool) Clear() {
	t.schedulerLock.Lock()
	defer t.schedulerLock.Unlock()

	t.scheduler.Clear()
	t.seenCache.Clear()
}

func (t *txPool) Scheduler() schedulingAPI.Scheduler {
	t.schedulerLock.Lock()
	defer t.schedulerLock.Unlock()

	return t.scheduler
}

func (t *txPool) WatchScheduler() (pubsub.ClosableSubscription, <-chan bool) {
	sub := t.schedulerNotifier.Subscribe()
	ch := make(chan bool)
	sub.Unwrap(ch)
	return sub, ch
}

func (t *txPool) WatchCheckedTransactions() (pubsub.ClosableSubscription, <-chan []*transaction.CheckedTransaction) {
	sub := t.checkTxNotifier.Subscribe()
	ch := make(chan []*transaction.CheckedTransaction)
	sub.Unwrap(ch)
	return sub, ch
}

func (t *txPool) getCurrentBlockInfo() (*BlockInfo, error) {
	t.blockInfoLock.Lock()
	defer t.blockInfoLock.Unlock()

	if t.blockInfo == nil {
		return nil, fmt.Errorf("no current block available")
	}
	return t.blockInfo, nil
}

// checkTxBatch requests the runtime to check the validity of a transaction batch.
// Transactions that pass the check are queued for scheduling.
func (t *txPool) checkTxBatch(ctx context.Context, rr host.RichRuntime) {
	batch := t.checkTxQueue.GetBatch()
	if len(batch) == 0 {
		return
	}

	bi, err := t.getCurrentBlockInfo()
	if err != nil {
		t.logger.Warn("failed to get current block info, unable to check transactions",
			"err", err,
		)
		return
	}

	rawTxBatch := make([][]byte, 0, len(batch))
	for _, item := range batch {
		rawTxBatch = append(rawTxBatch, item.Tx)
	}
	results, err := rr.CheckTx(ctx, bi.RuntimeBlock, bi.ConsensusBlock, bi.Epoch, bi.ActiveDescriptor.Executor.MaxMessages, rawTxBatch)
	if err != nil {
		t.logger.Warn("transaction batch check failed",
			"err", err,
		)
		// NOTE: We do not send the results back as the batch will be retried.
		return
	}

	// Remove the checked transaction batch.
	t.checkTxQueue.RemoveBatch(batch)

	txs := make([]*transaction.CheckedTransaction, 0, len(results))
	isLocal := make([]bool, 0, len(results))
	for i, res := range results {
		// Send back the result of running the checks.
		if batch[i].NotifyCh != nil {
			batch[i].NotifyCh <- &results[i]
			close(batch[i].NotifyCh)
		}

		if !res.IsSuccess() {
			t.logger.Debug("check tx failed", "tx", batch[i].Tx, "result", res)
			continue
		}

		txs = append(txs, res.ToCheckedTransaction(rawTxBatch[i]))
		isLocal = append(isLocal, batch[i].Meta.Local)
	}

	if len(txs) == 0 {
		return
	}

	t.logger.Debug("checked new transactions",
		"num_txs", len(txs),
	)

	// Queue checked transactions for scheduling.
	for i, tx := range txs {
		t.schedulerLock.Lock()
		// NOTE: Scheduler exists as otherwise there would be no current block info above.
		if err := t.scheduler.QueueTx(tx); err != nil {
			t.schedulerLock.Unlock()
			t.logger.Error("unable to schedule transaction", "tx", tx)
			continue
		}
		t.schedulerLock.Unlock()

		if err := t.seenCache.Put(tx.Hash(), time.Now()); err != nil {
			// cache.Put can only error if capacity in bytes is used and the
			// inserted value is too large. This should never happen in here.
			t.logger.Error("cache put error",
				"err", err,
			)
		}

		// Publish local transactions immediately.
		if isLocal[i] {
			if err := t.txPublisher.PublishTx(ctx, tx.Raw()); err != nil {
				t.logger.Warn("failed to publish local transaction",
					"err", err,
					"tx", tx,
				)
			}
		}
	}

	// Notify subscribers that we have received new transactions.
	t.checkTxNotifier.Broadcast(txs)
	t.schedulerNotifier.Broadcast(false)
}

func (t *txPool) ensureInitialized() error {
	select {
	case <-t.stopCh:
		return fmt.Errorf("shutting down")
	case <-t.initCh:
		return nil
	}
}

func (t *txPool) checkWorker() {
	defer close(t.quitCh)

	t.logger.Debug("starting transaction check worker")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-t.stopCh
		cancel()
	}()

	// Wait for the hosted runtime to be available.
	rr, err := t.host.WaitHostedRuntime(ctx)
	if err != nil {
		t.logger.Error("failed waiting for hosted runtime to become available",
			"err", err,
		)
		return
	}

	// Wait for initialization to make sure that we have the scheduler available.
	if err = t.ensureInitialized(); err != nil {
		return
	}

	for {
		select {
		case <-t.stopCh:
			return
		case <-t.checkTxCh.Out():
			// Check if there are any transactions to check and run the checks.
			t.checkTxBatch(ctx, rr)
		}
	}
}

func (t *txPool) republishWorker() {
	// Set up a ticker for republish interval.
	republishInterval := t.cfg.RepublishInterval
	if minRepublishInterval := t.txPublisher.GetMinRepublishInterval(); republishInterval < minRepublishInterval {
		republishInterval = minRepublishInterval
	}
	ticker := time.NewTicker(republishInterval)

	t.logger.Debug("starting transaction republish worker",
		"interval", republishInterval,
	)

	// Wait for initialization to make sure that we have the scheduler available.
	if err := t.ensureInitialized(); err != nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-t.stopCh
		cancel()
	}()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			// Get a batch of scheduled transactions.
			t.schedulerLock.Lock()
			txs := t.scheduler.GetBatch(true)
			t.schedulerLock.Unlock()

			if len(txs) == 0 {
				continue
			}

			// Filter transactions based on whether they can already be republished.
			var republishedCount int
			for _, tx := range txs {
				ts, seen := t.seenCache.Get(tx.Hash())
				if seen && time.Since(ts.(time.Time)) < republishInterval {
					continue
				}

				if err := t.txPublisher.PublishTx(ctx, tx.Raw()); err != nil {
					t.logger.Warn("failed to publish transaction",
						"err", err,
						"tx", tx,
					)
					continue
				}

				republishedCount++
			}

			t.logger.Debug("republished transactions",
				"num_txs", republishedCount,
			)
		}
	}
}

func (t *txPool) flushWorker() {
	// Wait for initialization to make sure that we have the scheduler available.
	if err := t.ensureInitialized(); err != nil {
		return
	}

	for {
		select {
		case <-t.stopCh:
			return
		case <-t.schedulerTicker.C:
			t.schedulerNotifier.Broadcast(true)
		}
	}
}

// New creates a new transaction pool instance.
func New(
	cfg *Config,
	host RuntimeHostProvisioner,
	txPublisher TransactionPublisher,
) (TransactionPool, error) {
	seenCache, err := lru.New(lru.Capacity(cfg.MaxLastSeenCacheSize, false))
	if err != nil {
		return nil, fmt.Errorf("error creating seen cache: %w", err)
	}

	return &txPool{
		logger:            logging.GetLogger("runtime/txpool"),
		stopCh:            make(chan struct{}),
		quitCh:            make(chan struct{}),
		initCh:            make(chan struct{}),
		cfg:               cfg,
		host:              host,
		txPublisher:       txPublisher,
		seenCache:         seenCache,
		checkTxQueue:      newCheckTxQueue(cfg.MaxPoolSize, cfg.MaxCheckTxBatchSize),
		checkTxCh:         channels.NewRingChannel(1),
		checkTxNotifier:   pubsub.NewBroker(false),
		schedulerTicker:   time.NewTicker(1 * time.Hour),
		schedulerNotifier: pubsub.NewBroker(false),
		roundWeightLimits: make(map[transaction.Weight]uint64),
	}, nil
}
