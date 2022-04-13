package txpool

import (
	"fmt"
	"sync"

	"github.com/google/btree"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

type item struct {
	tx *Transaction
}

func (i item) Less(other btree.Item) bool {
	// NOTE: We are iterating over the queue in descending order.
	i2 := other.(*item)
	if p1, p2 := i.tx.priority, i2.tx.priority; p1 != p2 {
		// Lower priority is first.
		return p1 < p2
	}
	// If transactions have same priority, sort by first seen time (newer first).
	return i.tx.time.After(i2.tx.time)
}

type priorityQueue struct {
	l sync.Mutex

	priorityIndex *btree.BTree
	transactions  map[hash.Hash]*item

	maxTxPoolSize int

	lowestPriority uint64
}

func (q *priorityQueue) add(tx *Transaction) error {
	q.l.Lock()
	defer q.l.Unlock()

	// Check if transaction already exists.
	if _, exists := q.transactions[tx.hash]; exists {
		return fmt.Errorf("tx already exists in pool")
	}

	// Check if there is room in the queue.
	var needsPop bool
	if len(q.transactions) >= q.maxTxPoolSize {
		needsPop = true

		if tx.priority <= q.lowestPriority {
			return fmt.Errorf("tx pool is full")
		}
	}

	// Remove the lowest priority transaction when queue is full.
	if needsPop {
		lpi := q.priorityIndex.Min()
		if lpi != nil {
			q.removeTxsLocked([]*item{lpi.(*item)})
		}
	}

	item := &item{tx: tx}
	q.priorityIndex.ReplaceOrInsert(item)
	q.transactions[tx.hash] = item
	if tx.priority < q.lowestPriority {
		q.lowestPriority = tx.priority
	}

	if mlen, qlen := len(q.transactions), q.priorityIndex.Len(); mlen != qlen {
		panic(fmt.Errorf("inconsistent sizes of the underlying index (%v) and map (%v) after Add", mlen, qlen))
	}

	return nil
}

func (q *priorityQueue) removeTxsLocked(items []*item) {
	for _, item := range items {
		// Skip already removed items to avoid corrupting the list in case of duplicates.
		if _, exists := q.transactions[item.tx.hash]; !exists {
			continue
		}

		delete(q.transactions, item.tx.hash)
		q.priorityIndex.Delete(item)
	}

	// Update lowest priority.
	if len(items) > 0 {
		if lpi := q.priorityIndex.Min(); lpi != nil {
			q.lowestPriority = lpi.(*item).tx.priority
		} else {
			q.lowestPriority = 0
		}
	}

	if mlen, qlen := len(q.transactions), q.priorityIndex.Len(); mlen != qlen {
		panic(fmt.Errorf("inconsistent sizes of the underlying index (%v) and map (%v) after removal", mlen, qlen))
	}
}

func (q *priorityQueue) getPrioritizedBatch(offset *hash.Hash, limit uint32) []*Transaction {
	q.l.Lock()
	defer q.l.Unlock()

	var (
		batch      []*Transaction
		offsetItem btree.Item
	)
	if offset != nil {
		var exists bool
		offsetItem, exists = q.transactions[*offset]
		if !exists {
			// Offset does not exist so no items will be matched anyway.
			return nil
		}
	}
	q.priorityIndex.DescendLessOrEqual(offsetItem, func(i btree.Item) bool {
		item := i.(*item)

		// Skip the offset item itself (if specified).
		if item.tx.hash.Equal(offset) {
			return true
		}

		// Add the tx to the batch.
		batch = append(batch, item.tx)
		if uint32(len(batch)) >= limit { //nolint: gosimple
			return false
		}
		return true
	})

	return batch
}

func (q *priorityQueue) getKnownBatch(batch []hash.Hash) ([]*Transaction, map[hash.Hash]int) {
	q.l.Lock()
	defer q.l.Unlock()

	result := make([]*Transaction, 0, len(batch))
	missing := make(map[hash.Hash]int)
	for index, txHash := range batch {
		if item, ok := q.transactions[txHash]; ok {
			result = append(result, item.tx)
		} else {
			result = append(result, nil)
			missing[txHash] = index
		}
	}
	return result, missing
}

func (q *priorityQueue) getAll() []*Transaction {
	q.l.Lock()
	defer q.l.Unlock()

	result := make([]*Transaction, 0, len(q.transactions))
	for _, item := range q.transactions {
		result = append(result, item.tx)
	}
	return result
}

func (q *priorityQueue) removeTxBatch(batch []hash.Hash) {
	q.l.Lock()
	defer q.l.Unlock()

	items := make([]*item, 0, len(batch))
	for _, txHash := range batch {
		if item, ok := q.transactions[txHash]; ok {
			items = append(items, item)
		}
	}
	q.removeTxsLocked(items)
}

func (q *priorityQueue) size() int {
	q.l.Lock()
	defer q.l.Unlock()

	return len(q.transactions)
}

func (q *priorityQueue) clear() {
	q.l.Lock()
	defer q.l.Unlock()

	q.priorityIndex.Clear(true)
	q.transactions = make(map[hash.Hash]*item)
	q.lowestPriority = 0
}

func newPriorityQueue(maxPoolSize int) *priorityQueue {
	return &priorityQueue{
		transactions:  make(map[hash.Hash]*item),
		priorityIndex: btree.New(2),
		maxTxPoolSize: maxPoolSize,
	}
}
