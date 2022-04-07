package txpool

import (
	"fmt"
	"sync"

	"github.com/google/btree"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	p2pError "github.com/oasisprotocol/oasis-core/go/worker/common/p2p/error"
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
	sync.Mutex

	priorityIndex *btree.BTree
	transactions  map[hash.Hash]*item

	maxTxPoolSize uint64

	poolWeights  map[transaction.Weight]uint64
	weightLimits map[transaction.Weight]uint64

	lowestPriority uint64
}

func (q *priorityQueue) add(tx *Transaction) error {
	q.Lock()
	defer q.Unlock()

	// Check if transaction already exists.
	if _, exists := q.transactions[tx.hash]; exists {
		return fmt.Errorf("tx already exists in pool")
	}

	// Check if there is room in the queue.
	var needsPop bool
	if q.poolWeights[transaction.WeightCount] >= q.maxTxPoolSize {
		needsPop = true

		if tx.priority <= q.lowestPriority {
			return fmt.Errorf("tx pool is full")
		}
	}

	// Check weights.
	for w, l := range q.weightLimits {
		txW := tx.weights[w]
		if txW > l {
			return p2pError.Permanent(fmt.Errorf("call too large"))
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
	for k, v := range tx.weights {
		q.poolWeights[k] += v
	}
	if tx.priority < q.lowestPriority {
		q.lowestPriority = tx.priority
	}

	if mlen, qlen := len(q.transactions), q.priorityIndex.Len(); mlen != qlen {
		panic(fmt.Errorf("inconsistent sizes of the underlying index (%v) and map (%v) after Add", mlen, qlen))
	}
	if mlen, plen := uint64(len(q.transactions)), q.poolWeights[transaction.WeightCount]; mlen != plen {
		panic(fmt.Errorf("inconsistent sizes of the map (%v) and pool weight count (%v) after Add", mlen, plen))
	}

	return nil
}

func (q *priorityQueue) getBatch(force bool) []*Transaction {
	q.Lock()
	defer q.Unlock()

	// Check if a batch is ready.
	var weightLimitReached bool
	for k, v := range q.weightLimits {
		if q.poolWeights[k] >= v {
			weightLimitReached = true
			break
		}
	}
	if !weightLimitReached && !force {
		return nil
	}

	minWeights := map[transaction.Weight]uint64{
		transaction.WeightCount:             1,
		transaction.WeightSizeBytes:         10,
		transaction.WeightConsensusMessages: 0,
	}

	var batch []*Transaction
	batchWeights := make(map[transaction.Weight]uint64)
	for w := range q.weightLimits {
		batchWeights[w] = 0
	}
	toRemove := []*item{}
	q.priorityIndex.Descend(func(i btree.Item) bool {
		item := i.(*item)

		// Check if the call fits into the batch.
		for w, limit := range q.weightLimits {
			batchWeight := batchWeights[w]

			txW := item.tx.weights[w]
			// Transaction weight greater than the limit. Drop the tx from the pool.
			if txW > limit {
				toRemove = append(toRemove, item)
				return true
			}

			// Stop if we can't actually fit anything in the batch.
			if limit-batchWeight < minWeights[w] {
				return false
			}

			// This transaction would overflow the batch.
			if batchWeight+txW > limit {
				return true
			}
		}

		// Add the tx to the batch.
		batch = append(batch, item.tx)
		for w, val := range item.tx.weights {
			if _, ok := batchWeights[w]; ok {
				batchWeights[w] += val
			}
		}

		return true
	})

	// Remove transactions discovered to be too big to even fit the batch.
	// This can happen if weight limits changed after the transaction was
	// already set to be scheduled.
	q.removeTxsLocked(toRemove)

	return batch
}

func (q *priorityQueue) removeTxsLocked(items []*item) {
	for _, item := range items {
		// Skip already removed items to avoid corrupting the list in case of duplicates.
		if _, exists := q.transactions[item.tx.hash]; !exists {
			continue
		}

		delete(q.transactions, item.tx.hash)
		q.priorityIndex.Delete(item)
		for k, v := range item.tx.weights {
			q.poolWeights[k] -= v
		}
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
	if mlen, plen := uint64(len(q.transactions)), q.poolWeights[transaction.WeightCount]; mlen != plen {
		panic(fmt.Errorf("inconsistent sizes of the map (%v) and pool weight count (%v) after removal", mlen, plen))
	}
}

func (q *priorityQueue) getPrioritizedBatch(offset *hash.Hash, limit uint32) []*Transaction {
	q.Lock()
	defer q.Unlock()

	var (
		batch      []*Transaction
		toRemove   []*item
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

		for w, l := range q.weightLimits {
			txW := item.tx.weights[w]
			// Transaction weight greater than the limit. Drop the tx from the pool.
			if txW > l {
				toRemove = append(toRemove, item)
				return true
			}
		}

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

	// Remove transactions discovered to be too big to even fit the batch.
	// This can happen if weight limits changed after the transaction was
	// already set to be scheduled.
	q.removeTxsLocked(toRemove)

	return batch
}

func (q *priorityQueue) getKnownBatch(batch []hash.Hash) ([]*Transaction, map[hash.Hash]int) {
	q.Lock()
	defer q.Unlock()

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
	q.Lock()
	defer q.Unlock()

	result := make([]*Transaction, 0, len(q.transactions))
	for _, item := range q.transactions {
		result = append(result, item.tx)
	}
	return result
}

func (q *priorityQueue) removeTxBatch(batch []hash.Hash) {
	q.Lock()
	defer q.Unlock()

	items := make([]*item, 0, len(batch))
	for _, txHash := range batch {
		if item, ok := q.transactions[txHash]; ok {
			items = append(items, item)
		}
	}
	q.removeTxsLocked(items)
}

func (q *priorityQueue) size() int {
	q.Lock()
	defer q.Unlock()

	return len(q.transactions)
}

func (q *priorityQueue) updateMaxPoolSize(maxPoolSize uint64) {
	q.Lock()
	defer q.Unlock()

	q.maxTxPoolSize = maxPoolSize
	// Any transaction not within the new limits will get removed during GetBatch iteration.
}

func (q *priorityQueue) updateWeightLimits(limits map[transaction.Weight]uint64) {
	q.Lock()
	defer q.Unlock()

	q.weightLimits = limits
	// Any transaction not within the new limits will get removed during GetBatch iteration.
}

func (q *priorityQueue) clear() {
	q.Lock()
	defer q.Unlock()

	q.priorityIndex.Clear(true)
	q.transactions = make(map[hash.Hash]*item)
	q.poolWeights = make(map[transaction.Weight]uint64)
	q.lowestPriority = 0
}

func newPriorityQueue(maxPoolSize uint64, weightLimits map[transaction.Weight]uint64) *priorityQueue {
	return &priorityQueue{
		transactions:  make(map[hash.Hash]*item),
		poolWeights:   make(map[transaction.Weight]uint64),
		priorityIndex: btree.New(2),
		maxTxPoolSize: maxPoolSize,
		weightLimits:  weightLimits,
	}
}
