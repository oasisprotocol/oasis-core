package txpool

import (
	"container/list"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/scheduling/simple/txpool/api"
)

type pendingTx struct {
	Tx       []byte
	TxHash   hash.Hash
	Meta     *TransactionMeta
	NotifyCh chan *protocol.CheckTxResult

	element *list.Element
}

// checkTxQueue is a queue backed by an ordered map.
type checkTxQueue struct {
	sync.Mutex

	transactions map[hash.Hash]*pendingTx
	queue        *list.List

	maxTxPoolSize uint64
	maxBatchSize  uint64
}

// Add adds transaction into the queue.
func (q *checkTxQueue) Add(tx *pendingTx) error {
	q.Lock()
	defer q.Unlock()

	// Check if there is room in the queue.
	if uint64(q.queue.Len()) >= q.maxTxPoolSize {
		return api.ErrFull
	}

	if err := q.checkTxLocked(tx.Tx, tx.TxHash); err != nil {
		return err
	}

	q.addTxLocked(tx)

	return nil
}

// GetBatch gets a batch of transactions from the queue.
func (q *checkTxQueue) GetBatch() []*pendingTx {
	q.Lock()
	defer q.Unlock()

	var batch []*pendingTx
	current := q.queue.Back()
	for {
		if current == nil {
			break
		}
		// Check if the batch already has enough transactions.
		if uint64(len(batch)) >= q.maxBatchSize {
			break
		}

		batch = append(batch, current.Value.(*pendingTx))
		current = current.Prev()
	}

	return batch
}

// RemoveBatch removes a batch of transactions from the queue.
func (q *checkTxQueue) RemoveBatch(batch []*pendingTx) {
	q.Lock()
	defer q.Unlock()

	for _, item := range batch {
		if pair, ok := q.transactions[item.TxHash]; ok {
			q.queue.Remove(pair.element)
			delete(q.transactions, item.TxHash)
			pair.element = nil
		}
	}
	if len(q.transactions) != q.queue.Len() {
		panic(fmt.Errorf("inconsistent sizes of the underlying list (%v) and map (%v) after RemoveBatch", q.queue.Len(), len(q.transactions)))
	}
}

// IsQueued checks if a transactions is already queued.
func (q *checkTxQueue) IsQueued(txHash hash.Hash) bool {
	q.Lock()
	defer q.Unlock()

	return q.isQueuedLocked(txHash)
}

// Size returns size of the queue.
func (q *checkTxQueue) Size() uint64 {
	q.Lock()
	defer q.Unlock()

	return uint64(q.queue.Len())
}

// Clear empties the queue.
func (q *checkTxQueue) Clear() {
	q.Lock()
	defer q.Unlock()

	q.queue = list.New()
	q.transactions = make(map[hash.Hash]*pendingTx)
}

// NOTE: Assumes lock is held.
func (q *checkTxQueue) isQueuedLocked(txHash hash.Hash) bool {
	_, ok := q.transactions[txHash]
	return ok
}

// NOTE: Assumes lock is held.
func (q *checkTxQueue) checkTxLocked(tx []byte, txHash hash.Hash) error {
	if q.isQueuedLocked(txHash) {
		return api.ErrCallAlreadyExists
	}

	return nil
}

// NOTE: Assumes lock is held and that checkTxLocked has been called.
func (q *checkTxQueue) addTxLocked(tx *pendingTx) {
	if tx.element != nil {
		return
	}

	// Assuming checkTxLocked has been called before, this can happen if
	// duplicate transactions are in the same batch -- just ignore them.
	if _, exists := q.transactions[tx.TxHash]; exists {
		return
	}

	tx.element = q.queue.PushFront(tx)
	q.transactions[tx.TxHash] = tx
}

// newCheckTxQueue creates a new check queue.
func newCheckTxQueue(maxPoolSize, maxBatchSize uint64) *checkTxQueue {
	return &checkTxQueue{
		transactions:  make(map[hash.Hash]*pendingTx),
		queue:         list.New(),
		maxTxPoolSize: maxPoolSize,
		maxBatchSize:  maxBatchSize,
	}
}
