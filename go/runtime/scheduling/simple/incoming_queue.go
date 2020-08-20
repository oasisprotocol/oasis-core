package simple

import (
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

var (
	errQueueFull         = errors.New("queue is full")
	errCallTooLarge      = errors.New("call too large")
	errCallAlreadyExists = errors.New("call already exists in queue")
	errNoBatchAvailable  = errors.New("no batch available in incoming queue")
)

type incomingQueue struct {
	sync.Mutex

	queue          transaction.RawBatch
	queueSizeBytes uint64
	callHashes     map[hash.Hash]bool

	maxQueueSize      uint64
	maxBatchSize      uint64
	maxBatchSizeBytes uint64
}

// Size returns the size of the incoming queue.
func (q *incomingQueue) Size() int {
	q.Lock()
	defer q.Unlock()

	return len(q.queue)
}

// Clear clears the queue.
func (q *incomingQueue) Clear() {
	q.Lock()
	defer q.Unlock()

	q.queue = make(transaction.RawBatch, 0)
	q.queueSizeBytes = 0
	q.callHashes = make(map[hash.Hash]bool)
}

// NOTE: Assumes lock is held.
func (q *incomingQueue) isQueuedLocked(callHash hash.Hash) bool {
	_, ok := q.callHashes[callHash]
	return ok
}

// IsQueued returns whether a call is in the queue already.
func (q *incomingQueue) IsQueued(callHash hash.Hash) bool {
	q.Lock()
	defer q.Unlock()

	return q.isQueuedLocked(callHash)
}

// NOTE: Assumes lock is held.
func (q *incomingQueue) checkCallLocked(call []byte, callHash hash.Hash) error {
	callSize := uint64(len(call))

	if callSize > q.maxBatchSizeBytes {
		return errCallTooLarge
	}
	if q.isQueuedLocked(callHash) {
		return errCallAlreadyExists
	}

	return nil
}

// NOTE: Assumes lock is held and that checkCallLocked has been called.
func (q *incomingQueue) addCallLocked(call []byte, callHash hash.Hash) {
	// Assuming checkCallLocked has been called before, this can happen if
	// duplicate calls are in the same batch -- just ignore them.
	if _, exists := q.callHashes[callHash]; exists {
		return
	}

	q.queue = append(q.queue, call)
	q.callHashes[callHash] = true
	q.queueSizeBytes += uint64(len(call))
}

func (q *incomingQueue) RemoveBatch(batch [][]byte) error {
	q.Lock()
	defer q.Unlock()

	for _, call := range batch {
		callHash := hash.NewFromBytes(call)
		if _, ok := q.callHashes[callHash]; !ok {
			continue
		}
		delete(q.callHashes, callHash)
	}

	var newQueue [][]byte
	var newSizeBytes uint64
	for _, call := range q.queue {
		callHash := hash.NewFromBytes(call)
		if _, ok := q.callHashes[callHash]; ok {
			newQueue = append(newQueue, call)
			newSizeBytes += uint64(len(call))
		}
	}
	q.queue = newQueue
	q.queueSizeBytes = newSizeBytes

	return nil
}

// Add adds a call to the incoming queue.
func (q *incomingQueue) Add(call []byte) error {
	callHash := hash.NewFromBytes(call)

	q.Lock()
	defer q.Unlock()

	// Check if there is room in the queue.
	if uint64(len(q.queue)) >= q.maxQueueSize {
		return errQueueFull
	}

	if err := q.checkCallLocked(call, callHash); err != nil {
		return err
	}

	q.addCallLocked(call, callHash)

	return nil
}

// AddBatch adds a batch of calls to the queue.
func (q *incomingQueue) AddBatch(batch transaction.RawBatch) error {
	// Compute all hashes before taking the lock.
	var callHashes []hash.Hash
	for _, call := range batch {
		callHash := hash.NewFromBytes(call)
		callHashes = append(callHashes, callHash)
	}

	q.Lock()
	defer q.Unlock()

	var errs error
	for i, call := range batch {
		if err := q.checkCallLocked(call, callHashes[i]); err != nil {
			errs = multierror.Append(errs, fmt.Errorf("failed inserting call: %d, error: %w", i, err))
			continue
		}

		// Check if there is room in the queue.
		if uint64(len(q.queue)) >= q.maxQueueSize {
			errs = multierror.Append(errs, fmt.Errorf("failed inserting call: %d, error: %w", i, errQueueFull))
			return errs
		}

		// Then add a call if checks passed.
		q.addCallLocked(call, callHashes[i])
	}

	return errs
}

// Take attempts to take a batch from the incoming queue.
func (q *incomingQueue) Take(force bool) (transaction.RawBatch, error) {
	q.Lock()
	defer q.Unlock()

	// Check if we have a batch ready.
	queueSize := uint64(len(q.queue))
	if queueSize == 0 {
		return nil, errNoBatchAvailable
	}
	if queueSize < q.maxBatchSize && q.queueSizeBytes < q.maxBatchSizeBytes && !force {
		return nil, errNoBatchAvailable
	}

	// NOTE: These "returned" variables signify what will be returned back
	//       to the queue, not what will be returned from the function.
	var returned transaction.RawBatch
	var returnedSizeBytes uint64
	returnedCallHashes := make(map[hash.Hash]bool)

	var batch transaction.RawBatch
	var batchSizeBytes uint64

	for _, call := range q.queue[:] {
		shouldReturn := false
		callSize := uint64(len(call))

		// Check if the batch already has enough calls.
		if uint64(len(batch)) >= q.maxBatchSize {
			shouldReturn = true
		}
		// Check if the call does not fit into a batch.
		if batchSizeBytes+callSize > q.maxBatchSizeBytes {
			shouldReturn = true
		}

		if shouldReturn {
			returned = append(returned, call)
			returnedSizeBytes += callSize

			callHash := hash.NewFromBytes(call)
			returnedCallHashes[callHash] = true
			continue
		}

		// Take call.
		batch = append(batch, call)
		batchSizeBytes += callSize
	}

	q.queue = returned
	q.queueSizeBytes = returnedSizeBytes
	q.callHashes = returnedCallHashes

	return batch, nil
}

func newIncomingQueue(maxQueueSize, maxBatchSize, maxBatchSizeBytes uint64) *incomingQueue {
	return &incomingQueue{
		callHashes:        make(map[hash.Hash]bool),
		maxQueueSize:      maxQueueSize,
		maxBatchSize:      maxBatchSize,
		maxBatchSizeBytes: maxBatchSizeBytes,
	}
}
