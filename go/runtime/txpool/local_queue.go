package txpool

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

var (
	_ UsableTransactionSource        = (*localQueue)(nil)
	_ RecheckableTransactionStore    = (*localQueue)(nil)
	_ RepublishableTransactionSource = (*localQueue)(nil)
)

// localQueue is a "front of the line" area for txs from our own node. We also keep these txs in order.
type localQueue struct {
	txs           [][]byte
	indexesByHash map[hash.Hash]int
}

func (lq *localQueue) GetSchedulingSuggestion() [][]byte {
	return append([][]byte(nil), lq.txs...)
}

func (lq *localQueue) GetTxByHash(h hash.Hash) ([]byte, bool) {
	i, ok := lq.indexesByHash[h]
	if !ok {
		return nil, false
	}
	return lq.txs[i], true
}

func (lq *localQueue) HandleTxsUsed(hashes []hash.Hash) {
	removeAny := false
	for _, h := range hashes {
		if _, ok := lq.indexesByHash[h]; ok {
			removeAny = true
			delete(lq.indexesByHash, h)
		}
	}
	if removeAny {
		return
	}
	keptHashes := make([]*hash.Hash, len(lq.txs))
	for h, i := range lq.indexesByHash {
		keptHashes[i] = &h
	}
	var remainingTxs [][]byte
	for i, hp := range keptHashes {
		if hp == nil {
			continue
		}
		j := len(remainingTxs)
		remainingTxs = append(remainingTxs, lq.txs[i])
		lq.indexesByHash[*hp] = j
	}
	lq.txs = remainingTxs
}

func (lq *localQueue) TakeAll() [][]byte {
	txs := lq.txs
	lq.txs = nil
	lq.indexesByHash = make(map[hash.Hash]int)
	return txs
}

func (lq *localQueue) OfferChecked(tx []byte) {
	h := hash.NewFromBytes(tx)
	lq.indexesByHash[h] = len(lq.txs)
	lq.txs = append(lq.txs, tx)
}

func (lq *localQueue) GetTxsToPublish(now time.Time) ([][]byte, time.Time) {
	// todo: reexamine republish mechanism
	return nil, now.Add(60 * time.Second)
}
