// Package mapp implements a tx pool backed by a map.
package mapp

import (
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

// Name is the name of the tx pool implementation.
const Name = "incoming-map"

var _ api.TxPool = (*incomingMap)(nil)

type incomingMap struct {
	sync.Mutex

	mapSizeBytes uint64
	calls        map[hash.Hash][]byte

	maxTxPoolSize     uint64
	maxBatchSize      uint64
	maxBatchSizeBytes uint64
}

// Implements api.TxPool.
func (q *incomingMap) Name() string {
	return Name
}

// Implements api.TxPool.
func (q *incomingMap) Add(tx []byte) error {
	txHash := hash.NewFromBytes(tx)

	q.Lock()
	defer q.Unlock()

	// Check if there is room in the queue.
	if uint64(len(q.calls)) >= q.maxTxPoolSize {
		return api.ErrFull
	}

	if err := q.checkTxLocked(tx, txHash); err != nil {
		return err
	}

	q.addTxLocked(tx, txHash)

	return nil
}

// Implements api.TxPool.
func (q *incomingMap) AddBatch(batch [][]byte) error {
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
		if uint64(len(q.calls)) >= q.maxTxPoolSize {
			errs = multierror.Append(errs, fmt.Errorf("failed inserting tx: %d, error: %w", i, api.ErrFull))
			return errs
		}

		// Add the tx if checks passed.
		q.addTxLocked(tx, txHashes[i])
	}

	return errs
}

// Implements api.TxPool.
func (q *incomingMap) GetBatch(force bool) [][]byte {
	q.Lock()
	defer q.Unlock()

	// Check if a batch is ready.
	queueSize := uint64(len(q.calls))
	if queueSize < q.maxBatchSize && q.mapSizeBytes < q.maxBatchSizeBytes && !force {
		return nil
	}

	var batch [][]byte
	var batchSizeBytes uint64
	for _, tx := range q.calls {
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
func (q *incomingMap) RemoveBatch(batch [][]byte) error {
	q.Lock()
	defer q.Unlock()

	for _, tx := range batch {
		txHash := hash.NewFromBytes(tx)
		if _, ok := q.calls[txHash]; !ok {
			continue
		}
		delete(q.calls, txHash)
		q.mapSizeBytes -= uint64(len(txHash))
	}

	return nil
}

// Implements api.TxPool.
func (q *incomingMap) IsQueued(txHash hash.Hash) bool {
	q.Lock()
	defer q.Unlock()

	return q.isQueuedLocked(txHash)
}

// Implements api.TxPool.
func (q *incomingMap) Size() uint64 {
	q.Lock()
	defer q.Unlock()

	return uint64(len(q.calls))
}

// Implements api.TxPool.
func (q *incomingMap) UpdateConfig(cfg api.Config) error {
	q.Lock()
	defer q.Unlock()
	q.maxBatchSize = cfg.MaxBatchSize
	q.maxBatchSizeBytes = cfg.MaxBatchSizeBytes
	q.maxTxPoolSize = cfg.MaxPoolSize

	// Recheck the queue for any calls that are bigger than the updated
	// `maxBatchSizeBytes`.
	var newMapSize uint64
	newTxs := make(map[hash.Hash][]byte)
	for hash, tx := range q.calls {
		txSize := uint64(len(tx))
		if txSize > cfg.MaxBatchSizeBytes {
			continue
		}

		if cfg.MaxPoolSize > uint64(len(newTxs)) {
			continue
		}

		newTxs[hash] = tx
		newMapSize += txSize
	}
	// Update queue.
	q.calls = newTxs
	q.mapSizeBytes = newMapSize

	return nil
}

// Implements api.TxPool.
func (q *incomingMap) IsQueue() bool {
	return false
}

// Implements api.TxPool.
func (q *incomingMap) Clear() {
	q.Lock()
	defer q.Unlock()

	q.mapSizeBytes = 0
	q.calls = make(map[hash.Hash][]byte)
}

// NOTE: Assumes lock is held.
func (q *incomingMap) isQueuedLocked(txHash hash.Hash) bool {
	_, ok := q.calls[txHash]
	return ok
}

// NOTE: Assumes lock is held.
func (q *incomingMap) checkTxLocked(tx []byte, txHash hash.Hash) error {
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
func (q *incomingMap) addTxLocked(tx []byte, txHash hash.Hash) {
	// Assuming checkTxLocked has been called before, this can happen if
	// duplicate calls are in the same batch -- just ignore them.
	if _, exists := q.calls[txHash]; exists {
		return
	}

	q.calls[txHash] = tx
	q.mapSizeBytes += uint64(len(tx))
}

// New returns a new incoming queue.
func New(cfg api.Config) api.TxPool {
	return &incomingMap{
		calls:             make(map[hash.Hash][]byte),
		maxTxPoolSize:     cfg.MaxPoolSize,
		maxBatchSize:      cfg.MaxBatchSize,
		maxBatchSizeBytes: cfg.MaxBatchSizeBytes,
	}
}
