package txpool

import (
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

var (
	_ UsableTransactionSource        = (*localQueue)(nil)
	_ RecheckableTransactionStore    = (*localQueue)(nil)
	_ RepublishableTransactionSource = (*localQueue)(nil)
)

// localQueue is a "front of the line" area for txs from our own node. We also keep these txs in order.
type localQueue struct {
	l             sync.Mutex
	txs           []*TxQueueMeta
	indexesByHash map[hash.Hash]int
}

func newLocalQueue() *localQueue {
	return &localQueue{
		indexesByHash: map[hash.Hash]int{},
	}
}

func (q *localQueue) GetSchedulingSuggestion(uint32) []*TxQueueMeta {
	q.l.Lock()
	defer q.l.Unlock()
	return append([]*TxQueueMeta(nil), q.txs...)
}

func (q *localQueue) GetTxByHash(h hash.Hash) *TxQueueMeta {
	q.l.Lock()
	defer q.l.Unlock()
	i, ok := q.indexesByHash[h]
	if !ok {
		return nil
	}
	return q.txs[i]
}

func (q *localQueue) HandleTxsUsed(hashes []hash.Hash) {
	q.l.Lock()
	defer q.l.Unlock()
	origCount := len(q.txs)
	keptCount := origCount
	for _, h := range hashes {
		if i, ok := q.indexesByHash[h]; ok {
			delete(q.indexesByHash, h)
			q.txs[i] = nil
			keptCount--
		}
	}
	if keptCount == origCount {
		return
	}
	keptTxs := make([]*TxQueueMeta, 0, keptCount)
	for _, tx := range q.txs {
		if tx == nil {
			continue
		}
		i := len(keptTxs)
		keptTxs = append(keptTxs, tx)
		q.indexesByHash[tx.Hash()] = i
	}
	q.txs = keptTxs
}

func (q *localQueue) PeekAll() []*TxQueueMeta {
	q.l.Lock()
	defer q.l.Unlock()
	return append(make([]*TxQueueMeta, 0, len(q.txs)), q.txs...)
}

func (q *localQueue) TakeAll() []*TxQueueMeta {
	q.l.Lock()
	defer q.l.Unlock()
	txs := q.txs
	q.txs = nil
	q.indexesByHash = make(map[hash.Hash]int)
	return txs
}

func (q *localQueue) OfferChecked(tx *TxQueueMeta, _ *protocol.CheckTxMetadata) error {
	q.l.Lock()
	defer q.l.Unlock()
	q.indexesByHash[tx.Hash()] = len(q.txs)
	q.txs = append(q.txs, tx)
	return nil
}

func (q *localQueue) GetTxsToPublish() []*TxQueueMeta {
	return q.PeekAll()
}

func (q *localQueue) size() int {
	q.l.Lock()
	defer q.l.Unlock()
	return len(q.txs)
}
