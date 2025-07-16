package txpool

import (
	"maps"
	"slices"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

var (
	_ UsableTransactionSource        = (*localQueue)(nil)
	_ RecheckableTransactionStore    = (*localQueue)(nil)
	_ RepublishableTransactionSource = (*localQueue)(nil)
)

// localQueue is a "front of the line" area for txs from our own node.
type localQueue struct {
	mu  sync.Mutex
	txs map[hash.Hash]*TxQueueMeta
}

func newLocalQueue() *localQueue {
	return &localQueue{
		txs: make(map[hash.Hash]*TxQueueMeta),
	}
}

func (q *localQueue) GetSchedulingSuggestion(int) []*TxQueueMeta {
	return q.PeekAll()
}

func (q *localQueue) GetTxByHash(h hash.Hash) (*TxQueueMeta, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	tx, ok := q.txs[h]
	return tx, ok
}

func (q *localQueue) HandleTxsUsed(hashes []hash.Hash) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, h := range hashes {
		delete(q.txs, h)
	}
}

func (q *localQueue) PeekAll() []*TxQueueMeta {
	q.mu.Lock()
	defer q.mu.Unlock()
	return slices.Collect(maps.Values(q.txs))
}

func (q *localQueue) TakeAll() []*TxQueueMeta {
	q.mu.Lock()
	defer q.mu.Unlock()
	txs := slices.Collect(maps.Values(q.txs))
	clear(q.txs)
	return txs
}

func (q *localQueue) OfferChecked(tx *TxQueueMeta, _ *protocol.CheckTxMetadata) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.txs[tx.Hash()] = tx
	return nil
}

func (q *localQueue) GetTxsToPublish() []*TxQueueMeta {
	return q.PeekAll()
}

func (q *localQueue) size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.txs)
}
