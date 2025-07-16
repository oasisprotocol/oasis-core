package txpool

import (
	"errors"
	"sync"

	"github.com/google/btree"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

var (
	ErrReplacementTxPriorityTooLow = errors.New("txpool: replacement tx priority too low")
	ErrQueueFull                   = errors.New("txpool: schedule queue is full")
)

// priorityLessFunc is a comparison function for ordering transactions by priority.
func priorityLessFunc(tx, tx2 *MainQueueTransaction) bool {
	switch {
	case tx == tx2:
		return false
	case tx == nil:
		return false // nil is last (descending order).
	case tx2 == nil:
		return true // nil is last (descending order).
	}

	// We are iterating over the queue in descending order, so we want higher priority transactions
	// to be later in the queue.
	if p1, p2 := tx.priority, tx2.priority; p1 != p2 {
		return p1 < p2
	}
	// If transactions have same priority, sort by first seen time (earlier transactions are later
	// in the queue as we are iterating over the queue in descending order).
	return tx.FirstSeen().After(tx2.FirstSeen())
}

type scheduleQueue struct {
	l sync.Mutex

	txs           map[hash.Hash]*MainQueueTransaction
	txsBySender   map[string]*MainQueueTransaction
	txsByPriority *btree.BTreeG[*MainQueueTransaction]

	capacity int
}

func newScheduleQueue(capacity int) *scheduleQueue {
	return &scheduleQueue{
		txs:           make(map[hash.Hash]*MainQueueTransaction),
		txsBySender:   make(map[string]*MainQueueTransaction),
		txsByPriority: btree.NewG(2, priorityLessFunc),
		capacity:      capacity,
	}
}

func (q *scheduleQueue) add(tx *MainQueueTransaction) error {
	q.l.Lock()
	defer q.l.Unlock()

	// If a transaction from the same sender already exists, we accept a new transaction only if it
	// has a higher priority or if the old transaction is no longer valid based on sequence numbers.
	if etx, exists := q.txsBySender[tx.sender]; exists {
		if etx.senderSeq >= tx.senderStateSeq && tx.priority <= etx.priority {
			return ErrReplacementTxPriorityTooLow
		}

		// Remove any existing transaction.
		q.removeLocked(etx)
	}

	// If the queue is full, we accept a new transaction only if it has a higher priority.
	if len(q.txs) >= q.capacity {
		// Attempt eviction.
		etx, _ := q.txsByPriority.Min()
		if tx.priority <= etx.priority {
			return ErrQueueFull
		}
		q.removeLocked(etx)
	}

	q.txs[tx.Hash()] = tx
	q.txsBySender[tx.sender] = tx
	q.txsByPriority.ReplaceOrInsert(tx)

	return nil
}

func (q *scheduleQueue) removeLocked(tx *MainQueueTransaction) {
	delete(q.txs, tx.Hash())
	delete(q.txsBySender, tx.sender)
	q.txsByPriority.Delete(tx)
}

func (q *scheduleQueue) remove(txHashes []hash.Hash) {
	q.l.Lock()
	defer q.l.Unlock()

	for _, txHash := range txHashes {
		tx, exists := q.txs[txHash]
		if !exists {
			continue
		}

		q.removeLocked(tx)
	}
}

func (q *scheduleQueue) getPrioritizedBatch(offset *hash.Hash, limit uint32) []*MainQueueTransaction {
	q.l.Lock()
	defer q.l.Unlock()

	var (
		batch      []*MainQueueTransaction
		offsetItem *MainQueueTransaction
	)
	if offset != nil {
		offsetTx, exists := q.txs[*offset]
		if !exists {
			// Offset does not exist so no items will be matched anyway.
			return nil
		}
		offsetItem = offsetTx
	}

	q.txsByPriority.DescendLessOrEqual(offsetItem, func(tx *MainQueueTransaction) bool {
		// Skip the offset item itself (if specified).
		h := tx.Hash()
		if h.Equal(offset) {
			return true
		}

		// Add the transaction to the batch.
		batch = append(batch, tx)
		if uint32(len(batch)) >= limit { // nolint: gosimple
			return false
		}
		return true
	})

	return batch
}

func (q *scheduleQueue) getKnownBatch(batch []hash.Hash) ([]*MainQueueTransaction, map[hash.Hash]int) {
	q.l.Lock()
	defer q.l.Unlock()

	result := make([]*MainQueueTransaction, 0, len(batch))
	missing := make(map[hash.Hash]int)
	for index, txHash := range batch {
		if tx, ok := q.txs[txHash]; ok {
			result = append(result, tx)
		} else {
			result = append(result, nil)
			missing[txHash] = index
		}
	}
	return result, missing
}

func (q *scheduleQueue) all() []*MainQueueTransaction {
	q.l.Lock()
	defer q.l.Unlock()

	result := make([]*MainQueueTransaction, 0, len(q.txs))
	for _, tx := range q.txs {
		result = append(result, tx)
	}
	return result
}

func (q *scheduleQueue) size() int {
	q.l.Lock()
	defer q.l.Unlock()

	return len(q.txs)
}

func (q *scheduleQueue) clear() {
	q.l.Lock()
	defer q.l.Unlock()

	q.txs = make(map[hash.Hash]*MainQueueTransaction)
	q.txsBySender = make(map[string]*MainQueueTransaction)
	q.txsByPriority.Clear(true)
}
