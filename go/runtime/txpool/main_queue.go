package txpool

import (
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// mainQueueTransaction is a transaction along with its metadata in the main queue.
type mainQueueTransaction struct {
	// meta contains the transaction metadata.
	meta *TxQueueMeta

	// sender is a unique transaction sender identifier as specified by the runtime.
	sender string

	// seq is a sender's sequence number as specified by the runtime.
	seq uint64

	// priority defines the transaction's priority as specified by the runtime.
	priority uint64

	// seqHeapIndex is the position in the sender's sequence heap where
	// transactions are sorted by sequence number.
	seqHeapIndex int

	// minHeapIndex is the position in the min-heap where all transactions are
	// sorted by the lowest priority.
	minHeapIndex int

	// maxHeapIndex is the position in the max-heap where the first pending
	// transaction from every sender are sorted by the highest priority.
	maxHeapIndex int
}

// newMainQueueTransaction creates a new transaction for the main queue.
func newMainQueueTransaction(meta *TxQueueMeta, sender string, seq uint64, priority uint64) *mainQueueTransaction {
	return &mainQueueTransaction{
		meta:         meta,
		sender:       sender,
		seq:          seq,
		priority:     priority,
		seqHeapIndex: -1,
		minHeapIndex: -1,
		maxHeapIndex: -1,
	}
}

// mainQueue is a priority queue for transactions that we give no special treatment.
type mainQueue struct {
	mu sync.Mutex

	// scheduler manages and prepares transactions for scheduling.
	scheduler *mainQueueScheduler
}

// newMainQueue creates a new main queue with the given capacity.
func newMainQueue(capacity int) *mainQueue {
	return &mainQueue{
		scheduler: newMainQueueScheduler(capacity),
	}
}

// GetSchedulingSuggestion implements UsableTransactionSource.
func (q *mainQueue) GetSchedulingSuggestion(limit int) []*TxQueueMeta {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.scheduler.reset()
	return q.scheduler.schedule(limit)
}

// GetSchedulingExtra returns more transactions to schedule.
func (q *mainQueue) GetSchedulingExtra(limit int) []*TxQueueMeta {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.scheduler.schedule(limit)
}

// GetTxByHash implements UsableTransactionSource.
func (q *mainQueue) GetTxByHash(hash hash.Hash) (*TxQueueMeta, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	tx, ok := q.scheduler.get(hash)
	if !ok {
		return nil, false
	}
	return tx.meta, true
}

// HandleTxsUsed implements UsableTransactionSource.
func (q *mainQueue) HandleTxsUsed(hashes []hash.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, hash := range hashes {
		q.scheduler.handleTxUsed(hash)
	}
}

// PeekAll implements UsableTransactionSource.
func (q *mainQueue) PeekAll() []*TxQueueMeta {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.scheduler.all()
}

// OfferChecked implements RecheckableTransactionStore.
func (q *mainQueue) OfferChecked(tx *TxQueueMeta, meta *protocol.CheckTxMetadata) error {
	t := newMainQueueTransaction(tx, string(meta.Sender), meta.SenderSeq, meta.Priority)

	q.mu.Lock()
	defer q.mu.Unlock()

	q.scheduler.forward(t.sender, meta.SenderStateSeq)
	return q.scheduler.add(t, meta.SenderStateSeq)
}

// TakeAll implements RecheckableTransactionStore.
func (q *mainQueue) TakeAll() []*TxQueueMeta {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.scheduler.drain()
}

// GetTxsToPublish implements RepublishableTransactionSource.
func (q *mainQueue) GetTxsToPublish() []*TxQueueMeta {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.scheduler.all()
}
