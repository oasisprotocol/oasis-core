// Package queue implements a tx pool backed by a queue.
package queue

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

// Name is the name of the tx pool implementation.
const Name = "incoming-queue"

var _ api.TxPool = (*incomingQueue)(nil)

type incomingQueue struct {
	sync.Mutex

	queue          [][]byte
	queueSizeBytes uint64
	txHashes       map[hash.Hash]bool

	maxTxPoolSize     uint64
	maxBatchSize      uint64
	maxBatchSizeBytes uint64
}

// Implements api.TxPool.
func (q *incomingQueue) Name() string {
	return Name
}

// Implements api.TxPool.
func (q *incomingQueue) Add(tx []byte) error {
	txHash := hash.NewFromBytes(tx)

	q.Lock()
	defer q.Unlock()

	// Check if there is room in the queue.
	if uint64(len(q.queue)) >= q.maxTxPoolSize {
		return api.ErrFull
	}

	if err := q.checkTxLocked(tx, txHash); err != nil {
		return err
	}

	q.addTxLocked(tx, txHash)

	return nil
}

// Implements api.TxPool.
func (q *incomingQueue) AddBatch(batch [][]byte) error {
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
		if uint64(len(q.queue)) >= q.maxTxPoolSize {
			errs = multierror.Append(errs, fmt.Errorf("failed inserting tx: %d, error: %w", i, api.ErrFull))
			return errs
		}

		// Add the tx if checks passed.
		q.addTxLocked(tx, txHashes[i])
	}

	return errs
}

// Implements api.TxPool.
func (q *incomingQueue) GetBatch(force bool) [][]byte {
	q.Lock()
	defer q.Unlock()

	// Check if a batch is ready.
	queueSize := uint64(len(q.queue))
	if queueSize < q.maxBatchSize && q.queueSizeBytes < q.maxBatchSizeBytes && !force {
		return nil
	}

	var batch [][]byte
	var batchSizeBytes uint64
	for _, tx := range q.queue[:] {
		txSize := uint64(len(tx))

		// Check if the batch already has enough calls.
		if uint64(len(batch)) >= q.maxBatchSize {
			break
		}
		// Check if the call does fit into the batch.
		// XXX: potentially there could still be smaller calls that would
		// fit, which this will miss.
		if batchSizeBytes+txSize > q.maxBatchSizeBytes {
			break
		}

		batch = append(batch, tx)
		batchSizeBytes += txSize
	}

	return batch
}

// Implements api.TxPool.
func (q *incomingQueue) RemoveBatch(batch [][]byte) error {
	q.Lock()
	defer q.Unlock()

	for _, tx := range batch {
		txHash := hash.NewFromBytes(tx)
		if _, ok := q.txHashes[txHash]; !ok {
			continue
		}
		delete(q.txHashes, txHash)
	}

	var newQueue [][]byte
	var newSizeBytes uint64
	for _, tx := range q.queue {
		txHash := hash.NewFromBytes(tx)
		if _, ok := q.txHashes[txHash]; ok {
			newQueue = append(newQueue, tx)
			newSizeBytes += uint64(len(tx))
		}
	}
	q.queue = newQueue
	q.queueSizeBytes = newSizeBytes

	return nil
}

// Implements api.TxPool.
func (q *incomingQueue) IsQueued(txHash hash.Hash) bool {
	q.Lock()
	defer q.Unlock()

	return q.isQueuedLocked(txHash)
}

// Implements api.TxPool.
func (q *incomingQueue) Size() uint64 {
	q.Lock()
	defer q.Unlock()

	return uint64(len(q.queue))
}

// Implements api.TxPool.
func (q *incomingQueue) UpdateConfig(cfg api.Config) error {
	q.Lock()
	defer q.Unlock()
	q.maxBatchSize = cfg.MaxBatchSize
	q.maxBatchSizeBytes = cfg.MaxBatchSizeBytes
	q.maxTxPoolSize = cfg.MaxPoolSize

	// Recheck the queue for any calls that are bigger than the updated
	// `maxBatchSizeBytes`.
	var newQueue [][]byte
	var newQueueSize uint64
	newCallHashes := make(map[hash.Hash]bool)
	for _, tx := range q.queue[:] {
		txSize := uint64(len(tx))
		if txSize > cfg.MaxBatchSizeBytes {
			continue
		}

		if cfg.MaxPoolSize > uint64(len(newQueue)) {
			continue
		}

		newQueue = append(newQueue, tx)
		newQueueSize += txSize
		txHash := hash.NewFromBytes(tx)
		newCallHashes[txHash] = true
	}
	// Update queue.
	q.queue = newQueue
	q.txHashes = newCallHashes
	q.queueSizeBytes = newQueueSize

	return nil
}

// Implements api.TxPool.
func (q *incomingQueue) IsQueue() bool {
	return true
}

// Implements api.TxPool.
func (q *incomingQueue) Clear() {
	q.Lock()
	defer q.Unlock()

	q.queue = make([][]byte, 0)
	q.queueSizeBytes = 0
	q.txHashes = make(map[hash.Hash]bool)
}

// NOTE: Assumes lock is held.
func (q *incomingQueue) isQueuedLocked(txHash hash.Hash) bool {
	_, ok := q.txHashes[txHash]
	return ok
}

// NOTE: Assumes lock is held.
func (q *incomingQueue) checkTxLocked(tx []byte, txHash hash.Hash) error {
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
func (q *incomingQueue) addTxLocked(tx []byte, txHash hash.Hash) {
	// Assuming checkTxLocked has been called before, this can happen if
	// duplicate calls are in the same batch -- just ignore them.
	if _, exists := q.txHashes[txHash]; exists {
		return
	}

	q.queue = append(q.queue, tx)
	q.txHashes[txHash] = true
	q.queueSizeBytes += uint64(len(tx))
}

// New returns a new incoming queue.
func New(cfg api.Config) api.TxPool {
	return &incomingQueue{
		txHashes:          make(map[hash.Hash]bool),
		maxTxPoolSize:     cfg.MaxPoolSize,
		maxBatchSize:      cfg.MaxBatchSize,
		maxBatchSizeBytes: cfg.MaxBatchSizeBytes,
	}
}
