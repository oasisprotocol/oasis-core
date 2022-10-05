package txpool

import (
	"fmt"
	"sync"

	"github.com/gammazero/deque"
)

type checkTxQueue struct {
	l sync.Mutex

	txs *deque.Deque[*PendingCheckTransaction]

	maxSize      int
	maxBatchSize int
}

func (cq *checkTxQueue) add(pct *PendingCheckTransaction) error {
	cq.l.Lock()
	defer cq.l.Unlock()

	// Check if there is room in the queue.
	if cq.txs.Len() >= cq.maxSize {
		return fmt.Errorf("check queue is full")
	}

	cq.txs.PushBack(pct)

	return nil
}

func (cq *checkTxQueue) retryBatch(pcts []*PendingCheckTransaction) {
	cq.l.Lock()
	defer cq.l.Unlock()

	// NOTE: This is meant for retries so it ignores the size limit on purpose.
	for _, pct := range pcts {
		cq.txs.PushFront(pct)
	}
}

func (cq *checkTxQueue) pop() []*PendingCheckTransaction {
	cq.l.Lock()
	defer cq.l.Unlock()

	var batch []*PendingCheckTransaction
	for {
		if cq.txs.Len() == 0 {
			break
		}

		// Check if the batch already has enough transactions.
		if len(batch) >= cq.maxBatchSize {
			break
		}

		tx := cq.txs.PopFront()
		batch = append(batch, tx)
	}

	return batch
}

func (cq *checkTxQueue) size() int {
	cq.l.Lock()
	defer cq.l.Unlock()

	return cq.txs.Len()
}

func (cq *checkTxQueue) clear() {
	cq.l.Lock()
	defer cq.l.Unlock()

	cq.txs.Clear()
}

func newCheckTxQueue(maxSize, maxBatchSize int) *checkTxQueue {
	return &checkTxQueue{
		txs:          deque.New[*PendingCheckTransaction](0, 512),
		maxSize:      maxSize,
		maxBatchSize: maxBatchSize,
	}
}
