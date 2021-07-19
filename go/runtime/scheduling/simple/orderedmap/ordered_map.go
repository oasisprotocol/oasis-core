// Package orderedmap implements a queue backed by an ordered map.
package orderedmap

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

type pair struct {
	Key   hash.Hash
	Value []byte

	element *list.Element
}

// OrderedMap is a queue backed by an ordered map.
type OrderedMap struct {
	sync.Mutex

	transactions map[hash.Hash]*pair
	queue        *list.List

	maxTxPoolSize uint64
	maxBatchSize  uint64
}

// Add adds transaction into the queue.
func (q *OrderedMap) Add(tx []byte) error {
	txHash := hash.NewFromBytes(tx)

	q.Lock()
	defer q.Unlock()

	// Check if there is room in the queue.
	if uint64(q.queue.Len()) >= q.maxTxPoolSize {
		return api.ErrFull
	}

	if err := q.checkTxLocked(tx, txHash); err != nil {
		return err
	}

	q.addTxLocked(tx, txHash)

	return nil
}

// AddBatch adds a batch of transactions into the queue.
func (q *OrderedMap) AddBatch(batch [][]byte) error {
	// Compute all hashes before taking the lock.
	var txHashes []hash.Hash
	for _, tx := range batch {
		txHash := hash.NewFromBytes(tx)
		txHashes = append(txHashes, txHash)
	}

	q.Lock()
	defer q.Unlock()

	var errs error
	for i, tx := range batch {
		if err := q.checkTxLocked(tx, txHashes[i]); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed inserting tx: %d, error: %w", i, err))
			continue
		}

		// Check if there is room in the queue.
		if uint64(q.queue.Len()) >= q.maxTxPoolSize {
			errs = multierror.Append(errs, fmt.Errorf("failed inserting tx: %d, error: %w", i, api.ErrFull))
			return errs
		}

		// Add the tx if checks passed.
		q.addTxLocked(tx, txHashes[i])
	}

	if len(q.transactions) != q.queue.Len() {
		panic(fmt.Errorf("inconsistent sizes of the underlying list (%v) and map (%v), after AddBatch", q.queue.Len(), len(q.transactions)))
	}

	return errs
}

// GetBatch gets a batch of transactions from the queue.
func (q *OrderedMap) GetBatch() [][]byte {
	q.Lock()
	defer q.Unlock()

	var batch [][]byte
	current := q.queue.Back()
	for {
		if current == nil {
			break
		}
		// Check if the batch already has enough transactions.
		if uint64(len(batch)) >= q.maxBatchSize {
			break
		}

		el := current.Value.(*pair)

		batch = append(batch, el.Value)
		current = current.Prev()
	}

	return batch
}

// RemoveBatch removes a batch of transactions from the queue.
func (q *OrderedMap) RemoveBatch(batch [][]byte) {
	q.Lock()
	defer q.Unlock()

	for _, tx := range batch {
		txHash := hash.NewFromBytes(tx)
		if pair, ok := q.transactions[txHash]; ok {
			q.queue.Remove(pair.element)
			delete(q.transactions, pair.Key)
		}
	}
	if len(q.transactions) != q.queue.Len() {
		panic(fmt.Errorf("inconsistent sizes of the underlying list (%v) and map (%v) after RemoveBatch", q.queue.Len(), len(q.transactions)))
	}
}

// IsQueued checks if a transactions is already queued.
func (q *OrderedMap) IsQueued(txHash hash.Hash) bool {
	q.Lock()
	defer q.Unlock()

	return q.isQueuedLocked(txHash)
}

// Size returns size of the queue.
func (q *OrderedMap) Size() uint64 {
	q.Lock()
	defer q.Unlock()

	return uint64(q.queue.Len())
}

// Clear empties the queue.
func (q *OrderedMap) Clear() {
	q.Lock()
	defer q.Unlock()

	q.queue = list.New()
	q.transactions = make(map[hash.Hash]*pair)
}

// NOTE: Assumes lock is held.
func (q *OrderedMap) isQueuedLocked(txHash hash.Hash) bool {
	_, ok := q.transactions[txHash]
	return ok
}

// NOTE: Assumes lock is held.
func (q *OrderedMap) checkTxLocked(tx []byte, txHash hash.Hash) error {
	if q.isQueuedLocked(txHash) {
		return api.ErrCallAlreadyExists
	}

	return nil
}

// NOTE: Assumes lock is held and that checkTxLocked has been called.
func (q *OrderedMap) addTxLocked(tx []byte, txHash hash.Hash) {
	// Assuming checkTxLocked has been called before, this can happen if
	// duplicate transactions are in the same batch -- just ignore them.
	if _, exists := q.transactions[txHash]; exists {
		return
	}
	p := &pair{
		Key:   txHash,
		Value: tx,
	}
	p.element = q.queue.PushFront(p)
	q.transactions[txHash] = p
}

// New returns a new incoming queue.
func New(maxPoolSize, maxBatchSize uint64) *OrderedMap {
	return &OrderedMap{
		transactions:  make(map[hash.Hash]*pair),
		queue:         list.New(),
		maxTxPoolSize: maxPoolSize,
		maxBatchSize:  maxBatchSize,
	}
}
