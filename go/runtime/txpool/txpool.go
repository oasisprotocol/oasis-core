package txpool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cache/lru"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/history"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool/config"
)

const (
	// checkTxTimeout is the maximum time the runtime can spend checking transactions.
	checkTxTimeout = 15 * time.Second
	// checkTxRetryDelay is the time to wait before queuing a check tx retry.
	checkTxRetryDelay = 1 * time.Second
	// abortTimeout is the maximum time the runtime can spend aborting.
	abortTimeout = 5 * time.Second
	// maxRepublishTxs is the maximum amount of transactions to republish.
	maxRepublishTxs = 128
	// newBlockPublishDelay is the time to wait to publish any newly checked transactions after
	// receiving a new block. It should be roughly the block propagation delay.
	newBlockPublishDelay = 200 * time.Millisecond

	// republishLimitReinvokeTimeout is the timeout to the next republish worker invocation in
	// case when the maxRepublishTxs limit is reached. This should be much shorter than the
	// RepublishInterval.
	republishLimitReinvokeTimeout = 1 * time.Second
)

// TransactionMeta contains the per-transaction metadata.
type TransactionMeta struct {
	// Local is a flag indicating that the transaction was obtained from a local client.
	Local bool

	// Discard is a flag indicating that the transaction should be discarded after checks.
	Discard bool
}

// TransactionPool is an interface for managing a pool of transactions.
type TransactionPool interface {
	// Start starts the service.
	Start() error

	// Stop halts the service.
	Stop()

	// Quit returns a channel that will be closed when the service terminates.
	Quit() <-chan struct{}

	// SubmitTx adds the transaction into the transaction pool, first performing checks on it by
	// invoking the runtime. This method waits for the checks to complete.
	SubmitTx(ctx context.Context, tx []byte, meta *TransactionMeta) (*protocol.CheckTxResult, error)

	// SubmitTxNoWait adds the transaction into the transaction pool and returns immediately.
	SubmitTxNoWait(tx []byte, meta *TransactionMeta) error

	// SubmitProposedBatch adds the given (possibly new) transaction batch into the current
	// proposal queue.
	SubmitProposedBatch(batch [][]byte)

	// PromoteProposedBatch promotes the specified transactions that are already in the transaction
	// pool into the current proposal queue and returns a set of known transactions.
	//
	// For any missing transactions nil will be returned in their place and the map of missing
	// transactions will be populated accordingly.
	PromoteProposedBatch(batch []hash.Hash) ([]*TxQueueMeta, map[hash.Hash]int)

	// ClearProposedBatch clears the proposal queue.
	ClearProposedBatch()

	// HandleTxsUsed indicates that given transaction hashes are processed in a block. Queues that
	// can remove those transactions will do so.
	HandleTxsUsed(txs []hash.Hash)

	// GetSchedulingSuggestion returns a list of transactions to schedule. This begins a
	// scheduling session, which suppresses transaction rechecking and republishing. Subsequently
	// call GetSchedulingExtra for more transactions, followed by FinishScheduling.
	GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta

	// GetSchedulingExtra returns transactions to schedule.
	//
	// Offset specifies the transaction hash that should serve as an offset when returning
	// transactions from the pool. Transactions will be skipped until the given hash is encountered
	// and only the following transactions will be returned.
	GetSchedulingExtra(offset *hash.Hash, limit uint32) []*TxQueueMeta

	// FinishScheduling finishes a scheduling session, which resumes transaction rechecking and
	// republishing.
	FinishScheduling()

	// GetKnownBatch gets a set of known transactions from the transaction pool.
	//
	// For any missing transactions nil will be returned in their place and the map of missing
	// transactions will be populated accordingly.
	GetKnownBatch(batch []hash.Hash) ([]*TxQueueMeta, map[hash.Hash]int)

	// ProcessBlock updates the last known runtime block information.
	ProcessBlock(bi *runtime.BlockInfo)

	// ProcessIncomingMessages loads transactions from incoming messages into the pool.
	ProcessIncomingMessages(inMsgs []*message.IncomingMessage)

	// WatchCheckedTransactions subscribes to notifications about new transactions being available
	// in the transaction pool for scheduling.
	WatchCheckedTransactions() (<-chan []*PendingCheckTransaction, pubsub.ClosableSubscription)

	// PendingCheckSize returns the number of transactions currently pending to be checked.
	PendingCheckSize() int
}

// RuntimeHostProvisioner is a runtime host provisioner.
type RuntimeHostProvisioner interface {
	// WaitHostedRuntime waits for the hosted runtime to be provisioned and returns it.
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

type txPool struct {
	logger *logging.Logger

	stopCh chan struct{}
	quitCh chan struct{}
	initCh chan struct{}

	runtimeID   common.Namespace
	cfg         config.Config
	host        RuntimeHostProvisioner
	txPublisher TransactionPublisher
	history     history.History

	// seenCache maps from transaction hashes to time.Time that specifies when the transaction was
	// last published.
	seenCache *lru.Cache

	checkTxCh       *channels.RingChannel
	checkTxQueue    *checkTxQueue
	checkTxNotifier *pubsub.Broker
	recheckTxCh     *channels.RingChannel

	drainLock sync.Mutex

	usableSources        []UsableTransactionSource
	recheckableStores    []RecheckableTransactionStore
	republishableSources []RepublishableTransactionSource
	rimQueue             *rimQueue
	localQueue           *localQueue
	mainQueue            *mainQueue

	proposedTxsLock sync.Mutex
	proposedTxs     map[hash.Hash]*TxQueueMeta

	blockInfoLock      sync.Mutex
	blockInfo          *runtime.BlockInfo
	lastBlockProcessed time.Time
	lastRecheckRound   uint64

	republishCh *channels.RingChannel
}

func (t *txPool) Start() error {
	go t.checkWorker()
	go t.republishWorker()
	go t.recheckWorker()
	return nil
}

func (t *txPool) Stop() {
	close(t.stopCh)
}

func (t *txPool) Quit() <-chan struct{} {
	return t.quitCh
}

func (t *txPool) SubmitTx(ctx context.Context, rawTx []byte, meta *TransactionMeta) (*protocol.CheckTxResult, error) {
	notifyCh := make(chan *protocol.CheckTxResult, 1)
	err := t.submitTx(rawTx, meta, notifyCh)
	if err != nil {
		close(notifyCh)
		return nil, err
	}

	// Wait for response from transaction checks.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.stopCh:
		return nil, fmt.Errorf("shutting down")
	case result := <-notifyCh:
		return result, nil
	}
}

func (t *txPool) SubmitTxNoWait(tx []byte, meta *TransactionMeta) error {
	return t.submitTx(tx, meta, nil)
}

func (t *txPool) submitTx(rawTx []byte, meta *TransactionMeta, notifyCh chan *protocol.CheckTxResult) error {
	tx := &TxQueueMeta{
		raw:       rawTx,
		hash:      hash.NewFromBytes(rawTx),
		firstSeen: time.Now(),
	}
	// Skip recently seen transactions.
	if _, seen := t.seenCache.Peek(tx.Hash()); seen {
		t.logger.Debug("ignoring already seen transaction", "tx_hash", tx.Hash())
		return fmt.Errorf("duplicate transaction")
	}

	// Queue transaction for checks.
	pct := &PendingCheckTransaction{
		TxQueueMeta: tx,
		notifyCh:    notifyCh,
	}
	if meta.Discard {
		pct.dstQueue = nil
	} else if meta.Local {
		pct.dstQueue = t.localQueue
	} else {
		pct.dstQueue = t.mainQueue
	}

	return t.addToCheckQueue(pct)
}

func (t *txPool) addToCheckQueue(pct *PendingCheckTransaction) error {
	t.logger.Debug("queuing transaction for check",
		"tx", pct.Raw(),
		"tx_hash", pct.Hash(),
		"recheck", pct.flags.isRecheck(),
	)
	if err := t.checkTxQueue.add(pct); err != nil {
		t.logger.Warn("unable to queue transaction",
			"tx_hash", pct.Hash(),
			"err", err,
		)
		return err
	}

	// Wake up the check batcher.
	t.checkTxCh.In() <- struct{}{}

	pendingCheckSize.With(t.getMetricLabels()).Set(float64(t.PendingCheckSize()))

	return nil
}

func (t *txPool) SubmitProposedBatch(batch [][]byte) {
	// Also ingest into the regular pool (may fail).
	for _, rawTx := range batch {
		_ = t.SubmitTxNoWait(rawTx, &TransactionMeta{Local: false})
	}

	t.proposedTxsLock.Lock()
	defer t.proposedTxsLock.Unlock()

	for _, rawTx := range batch {
		tx := &TxQueueMeta{
			raw:  rawTx,
			hash: hash.NewFromBytes(rawTx),
		}
		t.proposedTxs[tx.Hash()] = tx
	}
}

func (t *txPool) PromoteProposedBatch(batch []hash.Hash) ([]*TxQueueMeta, map[hash.Hash]int) {
	txs, missingTxs := t.GetKnownBatch(batch)
	if len(missingTxs) > 0 {
		t.logger.Debug("promoted proposed batch contains missing transactions",
			"missing_tx_count", len(missingTxs),
		)
	}

	t.proposedTxsLock.Lock()
	defer t.proposedTxsLock.Unlock()

	for _, tx := range txs {
		if tx == nil {
			continue
		}
		t.proposedTxs[tx.Hash()] = tx
	}

	return txs, missingTxs
}

func (t *txPool) ClearProposedBatch() {
	t.proposedTxsLock.Lock()
	defer t.proposedTxsLock.Unlock()

	t.proposedTxs = make(map[hash.Hash]*TxQueueMeta)
}

func (t *txPool) GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta {
	t.drainLock.Lock()
	var txs []*TxQueueMeta
	for _, q := range t.usableSources {
		txs = append(txs, q.GetSchedulingSuggestion(countHint)...)
	}
	return txs
}

func (t *txPool) GetSchedulingExtra(offset *hash.Hash, limit uint32) []*TxQueueMeta {
	return t.mainQueue.GetSchedulingExtra(offset, limit)
}

func (t *txPool) FinishScheduling() {
	t.drainLock.Unlock()
}

func (t *txPool) HandleTxsUsed(hashes []hash.Hash) {
	for _, q := range t.usableSources {
		q.HandleTxsUsed(hashes)
	}

	mainQueueSize.With(t.getMetricLabels()).Set(float64(t.mainQueue.inner.size()))
	localQueueSize.With(t.getMetricLabels()).Set(float64(t.localQueue.size()))
}

func (t *txPool) GetKnownBatch(batch []hash.Hash) ([]*TxQueueMeta, map[hash.Hash]int) {
	var txs []*TxQueueMeta
	missingTxs := make(map[hash.Hash]int)
HASH_LOOP:
	for i, h := range batch {
		for _, q := range t.usableSources {
			if tx := q.GetTxByHash(h); tx != nil {
				txs = append(txs, tx)
				continue HASH_LOOP
			}
		}
		txs = append(txs, nil)
		missingTxs[h] = i
	}

	// Also check the proposed transactions set.
	t.proposedTxsLock.Lock()
	defer t.proposedTxsLock.Unlock()

	for txHash, index := range missingTxs {
		tx, exists := t.proposedTxs[txHash]
		if !exists {
			continue
		}

		delete(missingTxs, txHash)
		txs[index] = tx
	}

	return txs, missingTxs
}

func (t *txPool) ProcessBlock(bi *runtime.BlockInfo) {
	t.blockInfoLock.Lock()
	defer t.blockInfoLock.Unlock()

	if t.blockInfo == nil {
		close(t.initCh)
	}

	t.blockInfo = bi
	t.lastBlockProcessed = time.Now()

	// Force transaction rechecks on epoch transitions and if needed.
	isEpochTransition := bi.RuntimeBlock.Header.HeaderType == block.EpochTransition
	roundDifference := bi.RuntimeBlock.Header.Round - t.lastRecheckRound
	if isEpochTransition || roundDifference > t.cfg.RecheckInterval {
		t.recheckTxCh.In() <- struct{}{}
		t.lastRecheckRound = bi.RuntimeBlock.Header.Round
	}
}

func (t *txPool) ProcessIncomingMessages(inMsgs []*message.IncomingMessage) {
	t.rimQueue.Load(inMsgs)
	rimQueueSize.With(t.getMetricLabels()).Set(float64(t.rimQueue.size()))
}

func (t *txPool) WatchCheckedTransactions() (<-chan []*PendingCheckTransaction, pubsub.ClosableSubscription) {
	sub := t.checkTxNotifier.Subscribe()
	ch := make(chan []*PendingCheckTransaction)
	sub.Unwrap(ch)
	return ch, sub
}

func (t *txPool) PendingCheckSize() int {
	return t.checkTxQueue.size()
}

func (t *txPool) getCurrentBlockInfo() (*runtime.BlockInfo, time.Time, error) {
	t.blockInfoLock.Lock()
	defer t.blockInfoLock.Unlock()

	if t.blockInfo == nil {
		return nil, time.Time{}, fmt.Errorf("no current block available")
	}
	return t.blockInfo, t.lastBlockProcessed, nil
}

// checkTxBatch requests the runtime to check the validity of a transaction batch.
// Transactions that pass the check are queued for scheduling.
func (t *txPool) checkTxBatch(ctx context.Context, rr host.RichRuntime) {
	bi, lastBlockProcessed, err := t.getCurrentBlockInfo()
	if err != nil {
		t.logger.Warn("failed to get current block info, unable to check transactions",
			"err", err,
		)
		return
	}

	batch := t.checkTxQueue.pop()
	if len(batch) == 0 {
		return
	}

	results, err := func() ([]protocol.CheckTxResult, error) {
		checkCtx, cancel := context.WithTimeout(ctx, checkTxTimeout)
		defer cancel()

		// Ensure block round is synced to storage.
		t.logger.Debug("ensuring block round is synced", "round", bi.RuntimeBlock.Header.Round)
		if _, err = t.history.WaitRoundSynced(checkCtx, bi.RuntimeBlock.Header.Round); err != nil {
			return nil, err
		}

		// Check batch.
		rawTxBatch := make([][]byte, 0, len(batch))
		for _, pct := range batch {
			rawTxBatch = append(rawTxBatch, pct.Raw())
		}
		return rr.CheckTx(checkCtx, bi.RuntimeBlock, bi.ConsensusBlock, bi.Epoch, bi.ActiveDescriptor.Executor.MaxMessages, rawTxBatch)
	}()
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled):
		// Context was canceled while the runtime was processing a request.
		t.logger.Error("transaction batch check aborted by context, aborting runtime")

		// Abort the runtime, so we can start processing the next batch.
		abortCtx, cancel := context.WithTimeout(ctx, abortTimeout)
		defer cancel()

		if err = rr.Abort(abortCtx, false); err != nil {
			t.logger.Error("failed to abort the runtime",
				"err", err,
			)
		}

		fallthrough
	default:
		t.logger.Warn("transaction batch check failed",
			"err", err,
		)

		// Return transaction batch back to the check queue.
		t.checkTxQueue.retryBatch(batch)

		// Make sure that the batch check is retried later.
		go func() {
			time.Sleep(checkTxRetryDelay)
			t.checkTxCh.In() <- struct{}{}
		}()
		return
	}

	pendingCheckSize.With(t.getMetricLabels()).Set(float64(t.PendingCheckSize()))

	notifySubmitter := func(i int) {
		// Send back the result of running the checks.
		if batch[i].notifyCh != nil {
			batch[i].notifyCh <- &results[i]
			close(batch[i].notifyCh)
			batch[i].notifyCh = nil
		}
	}

	newTxs := make([]*PendingCheckTransaction, 0, len(results))
	goodPcts := make([]*PendingCheckTransaction, 0, len(results))
	batchIndices := make([]int, 0, len(results))
	for i, res := range results {
		if !res.IsSuccess() {
			rejectedTransactions.With(t.getMetricLabels()).Inc()
			t.logger.Debug("check tx failed",
				"tx", batch[i].Raw(),
				"tx_hash", batch[i].Hash(),
				"result", res,
				"recheck", batch[i].flags.isRecheck(),
			)

			// We won't be sending this tx on to its destination queue.
			notifySubmitter(i)
			continue
		}

		if batch[i].dstQueue == nil {
			notifySubmitter(i)
			continue
		}

		// For any transactions that are to be queued, we defer notification until queued.

		if !batch[i].flags.isRecheck() {
			acceptedTransactions.With(t.getMetricLabels()).Inc()
			newTxs = append(newTxs, batch[i])
		}
		goodPcts = append(goodPcts, batch[i])
		batchIndices = append(batchIndices, i)
	}

	// If there are more transactions to check, make sure we check them next.
	if t.checkTxQueue.size() > 0 {
		t.checkTxCh.In() <- struct{}{}
	}

	if len(goodPcts) == 0 {
		return
	}

	t.logger.Debug("checked new transactions",
		"num_txs", len(newTxs),
		"accepted_txs", len(goodPcts),
	)

	// Queue checked transactions for scheduling.
	for i, pct := range goodPcts {
		if err = pct.dstQueue.OfferChecked(pct.TxQueueMeta, results[batchIndices[i]].Meta); err != nil {
			t.logger.Error("unable to queue transaction for scheduling",
				"err", err,
				"tx_hash", pct.Hash(),
			)

			// Change the result into an error and notify submitter.
			results[batchIndices[i]].Error = protocol.Error{
				Module:  "txpool",
				Code:    1,
				Message: err.Error(),
			}
			notifySubmitter(batchIndices[i])
			continue
		}

		// Notify submitter of success.
		notifySubmitter(batchIndices[i])

		if !pct.flags.isRecheck() {
			// Mark new transactions as never having been published. The republish worker will
			// publish these immediately.
			publishTime := time.Time{}
			if pct.dstQueue == t.mainQueue {
				// This being a tx we got from outside, it's usually something that another node
				// has just broadcast. Treat it as if it were published just now so that we don't
				// immediately publish again from our node.
				publishTime = time.Now()
			}
			// Put cannot fail as seenCache's LRU capacity is not in bytes and the only case where it
			// can error is if the capacity is in bytes and the value size is over capacity.
			_ = t.seenCache.Put(pct.Hash(), publishTime)
		}
	}

	if len(newTxs) != 0 {
		// Kick off publishing for any new txs after waiting for block publish delay based on when
		// we received the block that we just used to check the transaction batch.
		go func() {
			time.Sleep(time.Until(lastBlockProcessed.Add(newBlockPublishDelay)))
			t.republishCh.In() <- struct{}{}
		}()

		// Notify subscribers that we have received new transactions.
		t.checkTxNotifier.Broadcast(newTxs)
	}

	mainQueueSize.With(t.getMetricLabels()).Set(float64(t.mainQueue.inner.size()))
	localQueueSize.With(t.getMetricLabels()).Set(float64(t.localQueue.size()))
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

	// Wait for initialization.
	if err = t.ensureInitialized(); err != nil {
		return
	}

	for {
		select {
		case <-t.stopCh:
			return
		case <-t.checkTxCh.Out():
			t.logger.Debug("checking queued transactions")

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

	// Set up a debounce ticker for explicit republish requests.
	var (
		lastRepublish time.Time
		debounceCh    <-chan time.Time
		debounceTimer *time.Timer
	)
	const debounceInterval = 10 * time.Second
	defer func() {
		if debounceTimer == nil {
			return
		}

		if !debounceTimer.Stop() {
			<-debounceTimer.C
		}
	}()

	t.logger.Debug("starting transaction republish worker",
		"interval", republishInterval,
	)

	// Wait for initialization.
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
		case <-t.republishCh.Out():
			// Debounce explicit republish request.
			switch {
			case debounceCh != nil:
				// Debounce already in progress.
				continue
			case time.Since(lastRepublish) < debounceInterval:
				// Another request happened within the debounce interval, start timer.
				debounceTimer = time.NewTimer(debounceInterval - time.Since(lastRepublish))
				debounceCh = debounceTimer.C
				continue
			default:
				// Handle republish request.
			}
		case <-debounceCh:
			debounceCh = nil
		}

		// Get transactions to republish.
		var txs []*TxQueueMeta
		(func() {
			t.drainLock.Lock()
			defer t.drainLock.Unlock()
			for _, q := range t.republishableSources {
				txs = append(txs, q.GetTxsToPublish()...)
			}
		})()

		// Filter transactions based on whether they can already be republished.
		var republishedCount int
		nextPendingRepublish := republishInterval
		for _, tx := range txs {
			ts, seen := t.seenCache.Peek(tx.Hash())
			if seen {
				sinceLast := time.Since(ts.(time.Time))
				if sinceLast < republishInterval {
					if remaining := republishInterval - sinceLast; remaining < nextPendingRepublish {
						nextPendingRepublish = remaining + 1*time.Second
					}
					continue
				}
			}

			if err := t.txPublisher.PublishTx(ctx, tx.Raw()); err != nil {
				t.logger.Warn("failed to publish transaction",
					"err", err,
					"tx", tx,
				)
				t.republishCh.In() <- struct{}{}
				continue
			}

			// Update publish timestamp.
			_ = t.seenCache.Put(tx.Hash(), time.Now())

			republishedCount++
			if republishedCount >= maxRepublishTxs {
				// If the limit of max republish transactions has been reached
				// republish again sooner.
				nextPendingRepublish = republishLimitReinvokeTimeout
				break
			}
		}

		// Reschedule ticker for next republish.
		ticker.Reset(nextPendingRepublish)

		t.logger.Debug("republished transactions",
			"num_txs", republishedCount,
			"next_republish", nextPendingRepublish,
		)
	}
}

func (t *txPool) recheckWorker() {
	// Wait for initialization.
	if err := t.ensureInitialized(); err != nil {
		return
	}

	for {
		select {
		case <-t.stopCh:
			return
		case <-t.recheckTxCh.Out():
		}

		t.recheck()
	}
}

func (t *txPool) recheck() {
	t.drainLock.Lock()
	defer t.drainLock.Unlock()

	// Get a batch of scheduled transactions.
	var pcts []*PendingCheckTransaction
	var results []chan *protocol.CheckTxResult
	for _, q := range t.recheckableStores {
		for _, tx := range q.TakeAll() {
			notifyCh := make(chan *protocol.CheckTxResult, 1)
			pcts = append(pcts, &PendingCheckTransaction{
				TxQueueMeta: tx,
				flags:       txCheckRecheck,
				dstQueue:    q,
				notifyCh:    notifyCh,
			})
			results = append(results, notifyCh)
		}
	}
	mainQueueSize.With(t.getMetricLabels()).Set(float64(t.mainQueue.inner.size()))
	localQueueSize.With(t.getMetricLabels()).Set(float64(t.localQueue.size()))

	if len(pcts) == 0 {
		return
	}

	// Recheck all transactions in batch.
	for _, pct := range pcts {
		err := t.addToCheckQueue(pct)
		if err != nil {
			t.logger.Warn("failed to submit transaction for recheck",
				"err", err,
				"tx_hash", pct.Hash(),
			)
		}
	}

	// Block until checking is done.
	for _, notifyCh := range results {
		select {
		case <-t.stopCh:
			return
		case <-notifyCh:
			// Don't care about result.
		}
	}
}

// New creates a new transaction pool instance.
func New(
	runtimeID common.Namespace,
	cfg config.Config,
	host RuntimeHostProvisioner,
	history history.History,
	txPublisher TransactionPublisher,
) (TransactionPool, error) {
	initMetrics()

	seenCache, err := lru.New(lru.Capacity(cfg.MaxLastSeenCacheSize, false))
	if err != nil {
		return nil, fmt.Errorf("error creating seen cache: %w", err)
	}

	// The transaction check queue should be 10% larger than the transaction pool to allow for some
	// buffer in case the schedule queue is full and is being rechecked.
	maxCheckTxQueueSize := int((110 * cfg.MaxPoolSize) / 100)

	rq := newRimQueue()
	lq := newLocalQueue()
	mq := newMainQueue(int(cfg.MaxPoolSize))

	return &txPool{
		logger:               logging.GetLogger("runtime/txpool"),
		stopCh:               make(chan struct{}),
		quitCh:               make(chan struct{}),
		initCh:               make(chan struct{}),
		runtimeID:            runtimeID,
		cfg:                  cfg,
		host:                 host,
		history:              history,
		txPublisher:          txPublisher,
		seenCache:            seenCache,
		checkTxQueue:         newCheckTxQueue(maxCheckTxQueueSize, int(cfg.MaxCheckTxBatchSize)),
		checkTxCh:            channels.NewRingChannel(1),
		checkTxNotifier:      pubsub.NewBroker(false),
		recheckTxCh:          channels.NewRingChannel(1),
		usableSources:        []UsableTransactionSource{rq, lq, mq},
		recheckableStores:    []RecheckableTransactionStore{lq, mq},
		republishableSources: []RepublishableTransactionSource{lq, mq},
		rimQueue:             rq,
		localQueue:           lq,
		mainQueue:            mq,
		proposedTxs:          make(map[hash.Hash]*TxQueueMeta),
		republishCh:          channels.NewRingChannel(1),
	}, nil
}
