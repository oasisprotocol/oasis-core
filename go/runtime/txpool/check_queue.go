package txpool

import (
	"fmt"
	"sync"

	"github.com/gammazero/deque"
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

	// Check if there is room in the queue.
	if q.txs.Len() >= q.maxSize {
		return fmt.Errorf("check queue is full")
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

	batch := make([]*PendingCheckTransaction, 0, batchSize)
	for range batchSize {
		tx := q.txs.PopFront()
		batch = append(batch, tx)
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
