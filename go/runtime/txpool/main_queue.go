package txpool

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

var (
	_ UsableTransactionSource        = (*mainQueue)(nil)
	_ RecheckableTransactionStore    = (*mainQueue)(nil)
	_ RepublishableTransactionSource = (*mainQueue)(nil)
)

// mainQueue is a priority queue for transactions that we give no special treatment.
type mainQueue struct {
	// This implementation adapts the existing scheduleQueue code.
	inner *scheduleQueue
}

func newMainQueue(capacity int) *mainQueue {
	return &mainQueue{
		inner: newScheduleQueue(capacity),
	}
}

func (mq *mainQueue) GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta {
	txMetas := mq.inner.getPrioritizedBatch(nil, countHint)
	var txs []*TxQueueMeta
	for _, txMeta := range txMetas {
		txs = append(txs, &TxQueueMeta{
			Raw:  txMeta.tx,
			Hash: txMeta.hash,
		})
	}
	return txs
}

func (mq *mainQueue) GetTxByHash(h hash.Hash) (*TxQueueMeta, bool) {
	txMetas, _ := mq.inner.getKnownBatch([]hash.Hash{h})
	if txMetas[0] == nil {
		return nil, false
	}
	return &TxQueueMeta{
		Raw:  txMetas[0].tx,
		Hash: txMetas[0].hash,
	}, true
}

func (mq *mainQueue) HandleTxsUsed(hashes []hash.Hash) {
	mq.inner.remove(hashes)
}

func (mq *mainQueue) GetSchedulingExtra(offset *hash.Hash, limit uint32) []*TxQueueMeta {
	txMetas := mq.inner.getPrioritizedBatch(offset, limit)
	var txs []*TxQueueMeta
	for _, txMeta := range txMetas {
		txs = append(txs, &TxQueueMeta{
			Raw:  txMeta.tx,
			Hash: txMeta.hash,
		})
	}
	return txs
}

func (mq *mainQueue) TakeAll() []*TxQueueMeta {
	txMetas := mq.inner.getAll()
	mq.inner.clear()
	var txs []*TxQueueMeta
	for _, txMeta := range txMetas {
		txs = append(txs, &TxQueueMeta{
			Raw:  txMeta.tx,
			Hash: txMeta.hash,
		})
	}
	return txs
}

func (mq *mainQueue) OfferChecked(tx *TxQueueMeta, meta *protocol.CheckTxMetadata) error {
	txMeta := newTransaction(tx.Raw, txStatusChecked)
	if meta != nil {
		txMeta.priority = meta.Priority
		txMeta.sender = string(meta.Sender)
		txMeta.senderSeq = meta.SenderSeq
	}

	// If the sender is empty (e.g. because the runtime does not support specifying a sender), we
	// treat each transaction as having a unique sender. This is to allow backwards compatibility.
	if len(txMeta.sender) == 0 {
		txMeta.sender = string(txMeta.hash[:])
	}

	return mq.inner.add(txMeta)
}

func (mq *mainQueue) GetTxsToPublish() []*TxQueueMeta {
	txMetas := mq.inner.getAll()
	var txs []*TxQueueMeta
	for _, txMeta := range txMetas {
		txs = append(txs, &TxQueueMeta{
			Raw:  txMeta.tx,
			Hash: txMeta.hash,
		})
	}
	return txs
}
