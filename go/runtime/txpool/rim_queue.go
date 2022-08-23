package txpool

import (
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
)

var _ UsableTransactionSource = (*rimQueue)(nil)

// rimQueue exposes transactions form roothash incoming messages.
type rimQueue struct {
	l   sync.RWMutex
	txs map[hash.Hash]*TxQueueMeta
}

func newRimQueue() *rimQueue {
	return &rimQueue{
		txs: map[hash.Hash]*TxQueueMeta{},
	}
}

func (rq *rimQueue) GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta {
	// Runtimes instead get transactions from the incoming messages.
	return nil
}

func (rq *rimQueue) GetTxByHash(h hash.Hash) *TxQueueMeta {
	rq.l.RLock()
	defer rq.l.RUnlock()
	return rq.txs[h]
}

func (rq *rimQueue) HandleTxsUsed(hashes []hash.Hash) {
	// The roothash module manages the incoming message queue on its own, so we don't do anything here.
}

// Load loads transactions from roothash incoming messages.
func (rq *rimQueue) Load(inMsgs []*message.IncomingMessage) {
	newTxs := map[hash.Hash]*TxQueueMeta{}
	for _, msg := range inMsgs {
		h := hash.NewFromBytes(msg.Data)
		newTxs[h] = &TxQueueMeta{
			raw:  msg.Data,
			hash: h,
		}
	}
	rq.l.Lock()
	defer rq.l.Unlock()
	rq.txs = newTxs
}

func (rq *rimQueue) size() int {
	rq.l.Lock()
	defer rq.l.Unlock()
	return len(rq.txs)
}
