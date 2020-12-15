// Package orderedmap implements a tx pool backed by an ordered map.
package orderedmap

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

// Name is the name of the tx pool implementation.
const Name = "ordered-map"

var _ api.TxPool = (*orderedMap)(nil)

type pair struct {
	Key   hash.Hash
	Value []byte

	element *list.Element
}

type orderedMap struct {
	sync.Mutex

	transactions   map[hash.Hash]*pair
	queue          *list.List
	queueSizeBytes uint64

	maxTxPoolSize     uint64
	maxBatchSize      uint64
	maxBatchSizeBytes uint64
}

// Implements api.TxPool.
func (q *orderedMap) Name() string {
	return Name
}

// Implements api.TxPool.
func (q *orderedMap) Add(tx []byte) error {
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

// Implements api.TxPool.
func (q *orderedMap) AddBatch(batch [][]byte) error {
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

	return errs
}

// Implements api.TxPool.
func (q *orderedMap) GetBatch(force bool) [][]byte {
	q.Lock()
	defer q.Unlock()

	// Check if a batch is ready.
	queueSize := uint64(q.queue.Len())
	if queueSize < q.maxBatchSize && q.queueSizeBytes < q.maxBatchSizeBytes && !force {
		return nil
	}

	var batch [][]byte
	var batchSizeBytes uint64

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

		txSize := uint64(len(el.Value))
		// Check if the call does fit into the batch.
		// XXX: potentially there could still be smaller transactions that would
		// fit, which this will miss.
		if batchSizeBytes+txSize > q.maxBatchSizeBytes {
			break
		}

		batch = append(batch, el.Value)
		batchSizeBytes += txSize

		current = current.Prev()
	}

	return batch
}

// Implements api.TxPool.
func (q *orderedMap) RemoveBatch(batch [][]byte) error {
	q.Lock()
	defer q.Unlock()

	for _, tx := range batch {
		txHash := hash.NewFromBytes(tx)
		if pair, ok := q.transactions[txHash]; ok {
			q.queue.Remove(pair.element)
			delete(q.transactions, pair.Key)
			q.queueSizeBytes -= uint64(len(pair.Value))
		}
	}

	return nil
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
	q.maxBatchSize = cfg.MaxBatchSize
	q.maxBatchSizeBytes = cfg.MaxBatchSizeBytes
	q.maxTxPoolSize = cfg.MaxPoolSize

	// Recheck the queue for any transactions that are bigger than the updated
	// `maxBatchSizeBytes`.
	newQueue := list.New()
	var newMapSize uint64
	newTxs := make(map[hash.Hash]*pair)
	current := q.queue.Back()
	for {
		if current == nil {
			break
		}
		if uint64(newQueue.Len()) >= cfg.MaxPoolSize {
			break
		}
		el := current.Value.(*pair)
		txSize := uint64(len(el.Value))
		if txSize > cfg.MaxBatchSizeBytes {
			current = current.Prev()
			continue
		}
		newQueue.PushFront(el)
		newTxs[el.Key] = el
		newMapSize += txSize

		current = current.Prev()
	}

	// Update.
	q.queue = newQueue
	q.transactions = newTxs
	q.queueSizeBytes = newMapSize

	return nil
}

// Implements api.TxPool.
func (q *orderedMap) IsQueue() bool {
	return true
}

// Implements api.TxPool.
func (q *orderedMap) Clear() {
	q.Lock()
	defer q.Unlock()

	q.queue = list.New()
	q.queueSizeBytes = 0
	q.transactions = make(map[hash.Hash]*pair)
}

// NOTE: Assumes lock is held.
func (q *orderedMap) isQueuedLocked(txHash hash.Hash) bool {
	_, ok := q.transactions[txHash]
	return ok
}

// NOTE: Assumes lock is held.
func (q *orderedMap) checkTxLocked(tx []byte, txHash hash.Hash) error {
	txSize := uint64(len(tx))

	if txSize > q.maxBatchSizeBytes {
		return api.ErrCallTooLarge
	}
	if q.isQueuedLocked(txHash) {
		return api.ErrCallAlreadyExists
	}

	return nil
}

// NOTE: Assumes lock is held and that checkTxLocked has been called.
func (q *orderedMap) addTxLocked(tx []byte, txHash hash.Hash) {
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
	q.queueSizeBytes += uint64(len(tx))
}

// New returns a new incoming queue.
func New(cfg api.Config) api.TxPool {
	return &orderedMap{
		transactions:      make(map[hash.Hash]*pair),
		queue:             list.New(),
		maxTxPoolSize:     cfg.MaxPoolSize,
		maxBatchSize:      cfg.MaxBatchSize,
		maxBatchSizeBytes: cfg.MaxBatchSizeBytes,
	}
}
