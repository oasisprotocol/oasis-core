package txpool

import (
	"fmt"
	"sync"

	"github.com/gammazero/deque"
)

const (
	// maxBatchBytes is the maximum size of a batch in bytes.
	maxBatchBytes = 31 * 1024 * 1024 // 31MiB
)

type checkTxQueue struct {
	mu sync.Mutex

	txs *deque.Deque[*PendingCheckTransaction]

	maxSize      int
	maxBatchSize int
}

func newCheckTxQueue(maxSize, maxBatchSize int) *checkTxQueue {
	return &checkTxQueue{
		txs:          deque.New[*PendingCheckTransaction](0, 512),
		maxSize:      maxSize,
		maxBatchSize: maxBatchSize,
	}
}

func (q *checkTxQueue) add(pct *PendingCheckTransaction) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.txs.Len() >= q.maxSize {
		return fmt.Errorf("check queue is full")
	}

	if len(pct.raw) > maxBatchBytes {
		return fmt.Errorf("transaction is too large")
	}

	q.txs.PushBack(pct)

	return nil
}

func (q *checkTxQueue) retryBatch(pcts []*PendingCheckTransaction) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// NOTE: This is meant for retries so it ignores the size limit on purpose.
	for _, pct := range pcts {
		q.txs.PushFront(pct)
	}
}

func (q *checkTxQueue) pop() []*PendingCheckTransaction {
	q.mu.Lock()
	defer q.mu.Unlock()

	batchSize := min(q.txs.Len(), q.maxBatchSize)
	if batchSize == 0 {
		return nil
	}

	var batchBytes int

	batch := make([]*PendingCheckTransaction, 0, batchSize)
	for range batchSize {
		tx := q.txs.Front()

		batchBytes += len(tx.raw)
		if batchBytes > maxBatchBytes {
			break
		}
		batch = append(batch, tx)

		_ = q.txs.PopFront()
	}

	return batch
}

func (q *checkTxQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	return q.txs.Len()
}

func (q *checkTxQueue) clear() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.txs.Clear()
}
