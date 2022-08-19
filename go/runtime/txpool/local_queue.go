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

func (lq *localQueue) GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta {
	lq.l.Lock()
	defer lq.l.Unlock()
	return append([]*TxQueueMeta(nil), lq.txs...)
}

func (lq *localQueue) GetTxByHash(h hash.Hash) *TxQueueMeta {
	lq.l.Lock()
	defer lq.l.Unlock()
	i, ok := lq.indexesByHash[h]
	if !ok {
		return nil
	}
	return lq.txs[i]
}

func (lq *localQueue) HandleTxsUsed(hashes []hash.Hash) {
	lq.l.Lock()
	defer lq.l.Unlock()
	origCount := len(lq.txs)
	keptCount := origCount
	for _, h := range hashes {
		if i, ok := lq.indexesByHash[h]; ok {
			delete(lq.indexesByHash, h)
			lq.txs[i] = nil
			keptCount--
		}
	}
	if keptCount == origCount {
		return
	}
	keptTxs := make([]*TxQueueMeta, 0, keptCount)
	for _, tx := range lq.txs {
		if tx == nil {
			continue
		}
		i := len(keptTxs)
		keptTxs = append(keptTxs, tx)
		lq.indexesByHash[tx.Hash()] = i
	}
	lq.txs = keptTxs
}

func (lq *localQueue) TakeAll() []*TxQueueMeta {
	lq.l.Lock()
	defer lq.l.Unlock()
	txs := lq.txs
	lq.txs = nil
	lq.indexesByHash = make(map[hash.Hash]int)
	return txs
}

func (lq *localQueue) OfferChecked(tx *TxQueueMeta, _ *protocol.CheckTxMetadata) error {
	lq.l.Lock()
	defer lq.l.Unlock()
	lq.indexesByHash[tx.Hash()] = len(lq.txs)
	lq.txs = append(lq.txs, tx)
	return nil
}

func (lq *localQueue) GetTxsToPublish() []*TxQueueMeta {
	lq.l.Lock()
	defer lq.l.Unlock()
	return append([]*TxQueueMeta(nil), lq.txs...)
}

func (lq *localQueue) size() int {
	lq.l.Lock()
	defer lq.l.Unlock()
	return len(lq.txs)
}
