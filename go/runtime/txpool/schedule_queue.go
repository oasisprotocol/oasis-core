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

// priorityWrappedTx is a wrapped transaction for insertion into the priority B-Tree.
type priorityWrappedTx struct {
	*MainQueueTransaction
}

func (tx priorityWrappedTx) Less(other btree.Item) bool {
	// We are iterating over the queue in descending order, so we want higher priority transactions
	// to be later in the queue.
	tx2 := other.(priorityWrappedTx)
	if p1, p2 := tx.priority, tx2.priority; p1 != p2 {
		return p1 < p2
	}
	// If transactions have same priority, sort by first seen time (earlier transactions are later
	// in the queue as we are iterating over the queue in descending order).
	return tx.FirstSeen().After(tx2.FirstSeen())
}

type scheduleQueue struct {
	l sync.Mutex

	all        map[hash.Hash]*MainQueueTransaction
	bySender   map[string]*MainQueueTransaction
	byPriority *btree.BTree

	capacity int
}

func (sq *scheduleQueue) add(tx *MainQueueTransaction) error {
	sq.l.Lock()
	defer sq.l.Unlock()

	// If a transaction from the same sender already exists, we accept a new transaction only if it
	// has a higher priority.
	if etx, exists := sq.bySender[tx.sender]; exists {
		if tx.priority <= etx.priority {
			return ErrReplacementTxPriorityTooLow
		}

		// Remove any existing transaction.
		sq.removeLocked(etx)
	}

	// If the queue is full, we accept a new transaction only if it has a higher priority.
	if len(sq.all) >= sq.capacity {
		// Attempt eviction.
		etx := sq.byPriority.Min().(priorityWrappedTx)
		if tx.priority <= etx.priority {
			return ErrQueueFull
		}
		sq.removeLocked(etx.MainQueueTransaction)
	}

	sq.all[tx.Hash()] = tx
	sq.bySender[tx.sender] = tx
	sq.byPriority.ReplaceOrInsert(priorityWrappedTx{tx})

	return nil
}

func (sq *scheduleQueue) removeLocked(tx *MainQueueTransaction) {
	delete(sq.all, tx.Hash())
	delete(sq.bySender, tx.sender)
	sq.byPriority.Delete(priorityWrappedTx{tx})
}

func (sq *scheduleQueue) remove(txHashes []hash.Hash) {
	sq.l.Lock()
	defer sq.l.Unlock()

	for _, txHash := range txHashes {
		tx, exists := sq.all[txHash]
		if !exists {
			continue
		}

		sq.removeLocked(tx)
	}
}

func (sq *scheduleQueue) getPrioritizedBatch(offset *hash.Hash, limit uint32) []*MainQueueTransaction {
	sq.l.Lock()
	defer sq.l.Unlock()

	var (
		batch      []*MainQueueTransaction
		offsetItem btree.Item
	)
	if offset != nil {
		offsetTx, exists := sq.all[*offset]
		if !exists {
			// Offset does not exist so no items will be matched anyway.
			return nil
		}
		offsetItem = priorityWrappedTx{offsetTx}
	}

	sq.byPriority.DescendLessOrEqual(offsetItem, func(i btree.Item) bool {
		tx := i.(priorityWrappedTx)

		// Skip the offset item itself (if specified).
		h := tx.Hash()
		if h.Equal(offset) {
			return true
		}

		// Add the transaction to the batch.
		batch = append(batch, tx.MainQueueTransaction)
		if uint32(len(batch)) >= limit { // nolint: gosimple
			return false
		}
		return true
	})

	return batch
}

func (sq *scheduleQueue) getKnownBatch(batch []hash.Hash) ([]*MainQueueTransaction, map[hash.Hash]int) {
	sq.l.Lock()
	defer sq.l.Unlock()

	result := make([]*MainQueueTransaction, 0, len(batch))
	missing := make(map[hash.Hash]int)
	for index, txHash := range batch {
		if tx, ok := sq.all[txHash]; ok {
			result = append(result, tx)
		} else {
			result = append(result, nil)
			missing[txHash] = index
		}
	}
	return result, missing
}

func (sq *scheduleQueue) getAll() []*MainQueueTransaction {
	sq.l.Lock()
	defer sq.l.Unlock()

	result := make([]*MainQueueTransaction, 0, len(sq.all))
	for _, tx := range sq.all {
		result = append(result, tx)
	}
	return result
}

func (sq *scheduleQueue) size() int {
	sq.l.Lock()
	defer sq.l.Unlock()

	return len(sq.all)
}

func (sq *scheduleQueue) clear() {
	sq.l.Lock()
	defer sq.l.Unlock()

	sq.all = make(map[hash.Hash]*MainQueueTransaction)
	sq.bySender = make(map[string]*MainQueueTransaction)
	sq.byPriority.Clear(true)
}

func newScheduleQueue(capacity int) *scheduleQueue {
	return &scheduleQueue{
		all:        make(map[hash.Hash]*MainQueueTransaction),
		bySender:   make(map[string]*MainQueueTransaction),
		byPriority: btree.New(2),
		capacity:   capacity,
	}
}
