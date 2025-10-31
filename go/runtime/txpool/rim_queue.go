package txpool

import (
	"maps"
	"slices"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

// rimQueue exposes transactions from roothash incoming messages.
type rimQueue struct {
	mu  sync.RWMutex
	txs map[hash.Hash]*TxQueueMeta
}

func newRimQueue() *rimQueue {
	return &rimQueue{
		txs: make(map[hash.Hash]*TxQueueMeta),
	}
}

// Get implements UsableTransactionSource.
func (q *rimQueue) Get(h hash.Hash) (*TxQueueMeta, bool) {
	q.mu.RLock()
	defer q.mu.RUnlock()
	tx, ok := q.txs[h]
	return tx, ok
}

// All implements UsableTransactionSource.
func (q *rimQueue) All() []*TxQueueMeta {
	q.mu.RLock()
	defer q.mu.RUnlock()

	return slices.Collect(maps.Values(q.txs))
}

// Load loads transactions from roothash incoming messages.
func (q *rimQueue) Load(inMsgs []*message.IncomingMessage) {
	newTxs := map[hash.Hash]*TxQueueMeta{}
	for _, msg := range inMsgs {
		h := hash.NewFromBytes(msg.Data)
		newTxs[h] = &TxQueueMeta{
			raw:  msg.Data,
			hash: h,
		}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.txs = newTxs
}

func (q *rimQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.txs)
}
