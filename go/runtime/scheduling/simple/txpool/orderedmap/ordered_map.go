// Package orderedmap implements a tx pool backed by an ordered map.
//
// Orderedmap orders the transactions by insertion time, and doesn't support
// ordering by priority.
package orderedmap

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

// Name is the name of the tx pool implementation.
const Name = "ordered-map"

var _ api.TxPool = (*orderedMap)(nil)

type pair struct { // TODO: remove key?
	Key   hash.Hash
	Value *transaction.CheckedTransaction

	element *list.Element
}

type orderedMap struct {
	sync.Mutex

	transactions map[hash.Hash]*pair
	queue        *list.List

	maxTxPoolSize uint64

	weightLimits map[string]uint64
}

// Implements api.TxPool.
func (q *orderedMap) Name() string {
	return Name
}

// Implements api.TxPool.
func (q *orderedMap) Add(tx *transaction.CheckedTransaction) error {
	q.Lock()
	defer q.Unlock()

	// Check if there is room in the queue.
	if uint64(q.queue.Len()) >= q.maxTxPoolSize {
		return api.ErrFull
	}

	if err := q.checkTxLocked(tx); err != nil {
		return err
	}

	p := &pair{
		Key:   tx.Hash(),
		Value: tx,
	}
	p.element = q.queue.PushFront(p)
	q.transactions[tx.Hash()] = p

	return nil
}

// Implements api.TxPool.
func (q *orderedMap) GetBatch(force bool) []*transaction.CheckedTransaction {
	q.Lock()
	defer q.Unlock()

	// Check if a batch is ready.
	queueSize := uint64(q.queue.Len())
	// TODO: could also check if any other weight limits are reached.
	if queueSize < q.weightLimits[transaction.WeightCount] && !force {
		return nil
	}

	var batch []*transaction.CheckedTransaction
	batchWeights := make(map[string]uint64)
	for w := range q.weightLimits {
		batchWeights[w] = 0
	}

	current := q.queue.Back()
OUTER:
	for {

		if current == nil {
			break
		}

		el := current.Value.(*pair)

		// Check if the call does fit into the batch.
		// XXX: potentially there could still be smaller transactions that would
		// fit, which this will miss.
		// TODO: Could do some lookahead.

		// Check if any weight limit is reached.
		for w, limit := range q.weightLimits {
			batchWeight := batchWeights[w]

			// Check if the transaction itself can even be scheduled. Drop it if not.
			txW := el.Value.Weight(w)
			// Transaction weight greater than the limit. Drop the tx from the pool.
			if txW > limit {
				current = current.Prev()
				q.removeElementLocked(el)
				continue OUTER
			}

			// Batch full, schedule the batch. TODO: could do some lookahead.
			if batchWeight+txW > limit {
				break OUTER
			}

			// Check if transaction can be included in the batch.
			if batchWeight+txW > limit {
				break OUTER
			}
		}

		batch = append(batch, el.Value)
		for k, v := range el.Value.Weights() {
			if _, ok := batchWeights[k]; ok {
				batchWeights[k] += v
			}
		}

		current = current.Prev()
	}

	return batch
}

// Implements api.TxPool.
func (q *orderedMap) RemoveBatch(batch []hash.Hash) error {
	q.Lock()
	defer q.Unlock()

	for _, txHash := range batch {
		if pair, ok := q.transactions[txHash]; ok {
			q.queue.Remove(pair.element)
			delete(q.transactions, pair.Key)
		}
	}
	if len(q.transactions) != q.queue.Len() {
		panic(fmt.Errorf("inconsistent sizes of the underlying list (%v) and map (%v) after RemoveBatch", q.queue.Len(), len(q.transactions)))
	}

	return nil
}

func (q *orderedMap) removeElementLocked(pair *pair) {
	q.queue.Remove(pair.element)
	delete(q.transactions, pair.Key)

	if len(q.transactions) != q.queue.Len() {
		panic(fmt.Errorf("inconsistent sizes of the underlying list (%v) and map (%v) after RemoveBatch", q.queue.Len(), len(q.transactions)))
	}
}

// Implements api.TxPool.
func (q *orderedMap) IsQueued(txHash hash.Hash) bool {
	q.Lock()
	defer q.Unlock()

	return q.isQueuedLocked(txHash)
}

// Implements api.TxPool.
func (q *orderedMap) Size() uint64 {
	q.Lock()
	defer q.Unlock()

	return uint64(q.queue.Len())
}

// Implements api.TxPool.
func (q *orderedMap) UpdateConfig(cfg api.Config) error {
	q.Lock()
	defer q.Unlock()
	q.maxTxPoolSize = cfg.MaxPoolSize
	q.weightLimits = cfg.WeightLimits

	// Any transaction not within the new limits will get removed during GetBatch iteration.

	return nil
}

// Implements api.TxPool.
func (q *orderedMap) Clear() {
	q.Lock()
	defer q.Unlock()

	q.queue = list.New()
	q.transactions = make(map[hash.Hash]*pair)
}

// NOTE: Assumes lock is held.
func (q *orderedMap) isQueuedLocked(txHash hash.Hash) bool {
	_, ok := q.transactions[txHash]
	return ok
}

// NOTE: Assumes lock is held.
func (q *orderedMap) checkTxLocked(tx *transaction.CheckedTransaction) error {
	// Check weights.
	for w, l := range q.weightLimits {
		txW := tx.Weight(w)
		if txW > l {
			// Transaction weight greater than the limit.
			return fmt.Errorf("transaction doesn't fit batch weight limit: %w", api.ErrCallTooLarge)
		}
	}

	if q.isQueuedLocked(tx.Hash()) {
		return api.ErrCallAlreadyExists
	}

	return nil
}

// New returns a new incoming queue.
func New(cfg api.Config) api.TxPool {
	return &orderedMap{
		transactions:  make(map[hash.Hash]*pair),
		queue:         list.New(),
		maxTxPoolSize: cfg.MaxPoolSize,
		weightLimits:  cfg.WeightLimits,
	}
}
