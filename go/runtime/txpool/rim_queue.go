package txpool

import (
	"maps"
	"slices"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

var _ UsableTransactionSource = (*rimQueue)(nil)

// rimQueue exposes transactions from roothash incoming messages.
type rimQueue struct {
	l   sync.RWMutex
	txs map[hash.Hash]*TxQueueMeta
}

func newRimQueue() *rimQueue {
	return &rimQueue{
		txs: make(map[hash.Hash]*TxQueueMeta),
	}
}

func (q *rimQueue) GetSchedulingSuggestion(int) []*TxQueueMeta {
	// Runtimes instead get transactions from the incoming messages.
	return nil
}

func (q *rimQueue) GetTxByHash(h hash.Hash) *TxQueueMeta {
	q.l.RLock()
	defer q.l.RUnlock()
	return q.txs[h]
}

func (q *rimQueue) HandleTxsUsed([]hash.Hash) {
	// The roothash module manages the incoming message queue on its own, so we don't do anything here.
}

func (q *rimQueue) PeekAll() []*TxQueueMeta {
	q.l.RLock()
	defer q.l.RUnlock()

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
	q.l.Lock()
	defer q.l.Unlock()
	q.txs = newTxs
}

func (q *rimQueue) size() int {
	q.l.Lock()
	defer q.l.Unlock()
	return len(q.txs)
}
