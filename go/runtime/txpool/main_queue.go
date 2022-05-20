package txpool

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
)

var (
	_ UsableTransactionSource     = (*mainQueue)(nil)
	_ RecheckableTransactionStore = (*mainQueue)(nil)
)

// mainQueue is a priority queue for transactions that we give no special treatment.
type mainQueue struct {
	// This implementation adapts the existing scheduleQueue code.
	inner scheduleQueue
}

func (mq *mainQueue) GetSchedulingSuggestion() [][]byte {
	txMetas := mq.inner.getPrioritizedBatch(nil, 50)
	var txs [][]byte
	for _, txMeta := range txMetas {
		txs = append(txs, txMeta.tx)
	}
	return txs
}

func (mq *mainQueue) GetTxByHash(h hash.Hash) ([]byte, bool) {
	txMetas, _ := mq.inner.getKnownBatch([]hash.Hash{h})
	if txMetas[0] == nil {
		return nil, false
	}
	return txMetas[0].tx, true
}

func (mq *mainQueue) HandleTxsUsed(hashes []hash.Hash) {
	mq.inner.remove(hashes)
}

func (mq *mainQueue) TakeAll() [][]byte {
	txMetas := mq.inner.getAll()
	mq.inner.clear()
	var txs [][]byte
	for _, txMeta := range txMetas {
		txs = append(txs, txMeta.tx)
	}
	return txs
}

func (mq *mainQueue) OfferChecked(tx []byte) {
	txMeta := newTransaction(tx, txStatusChecked)
	if err := mq.inner.add(txMeta); err != nil {
		logging.GetLogger("mainQueue").Warn("offerChecked tx not wanted",
			"hash", txMeta.hash,
			"err", err,
		)
	}
}
