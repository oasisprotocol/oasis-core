package txpool

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

var (
	_ UsableTransactionSource        = (*mainQueue)(nil)
	_ RecheckableTransactionStore    = (*mainQueue)(nil)
	_ RepublishableTransactionSource = (*mainQueue)(nil)
)

// MainQueueTransaction is a transaction and its metadata in the main queue.
type MainQueueTransaction struct {
	TxQueueMeta

	// priority defines the transaction's priority as specified by the runtime.
	priority uint64

	// sender is a unique transaction sender identifier as specified by the runtime.
	sender string
	// senderSeq is a per-sender sequence number as specified by the runtime.
	senderSeq uint64
	// senderStateSeq is the current (as of when the check was performed) sequence number of the
	// sender stored in runtime state.
	senderStateSeq uint64
}

func newTransaction(tx TxQueueMeta) *MainQueueTransaction {
	return &MainQueueTransaction{
		TxQueueMeta: tx,
	}
}

// String returns a string representation of a transaction.
func (tx *MainQueueTransaction) String() string {
	return fmt.Sprintf("MainQueueTransaction{hash: %s, first_seen: %s, priority: %d}", tx.Hash(), tx.FirstSeen(), tx.priority)
}

// Priority returns the transaction priority.
func (tx *MainQueueTransaction) Priority() uint64 {
	return tx.priority
}

// Sender returns the transaction sender.
func (tx *MainQueueTransaction) Sender() string {
	return tx.sender
}

// SenderSeq returns the per-sender sequence number.
func (tx *MainQueueTransaction) SenderSeq() uint64 {
	return tx.senderSeq
}

// setChecked populates transaction data retrieved from checks.
func (tx *MainQueueTransaction) setChecked(meta *protocol.CheckTxMetadata) {
	if meta != nil {
		tx.priority = meta.Priority
		tx.sender = string(meta.Sender)
		tx.senderSeq = meta.SenderSeq
		tx.senderStateSeq = meta.SenderStateSeq
	}

	// If the sender is empty (e.g. because the runtime does not support specifying a sender), we
	// treat each transaction as having a unique sender. This is to allow backwards compatibility.
	if len(tx.sender) == 0 {
		h := tx.Hash()
		tx.sender = string(h[:])
	}
}

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
		txs = append(txs, &txMeta.TxQueueMeta)
	}
	return txs
}

func (mq *mainQueue) GetTxByHash(h hash.Hash) *TxQueueMeta {
	txMetas, _ := mq.inner.getKnownBatch([]hash.Hash{h})
	if txMetas[0] == nil {
		return nil
	}
	return &txMetas[0].TxQueueMeta
}

func (mq *mainQueue) HandleTxsUsed(hashes []hash.Hash) {
	mq.inner.remove(hashes)
}

func (mq *mainQueue) GetSchedulingExtra(offset *hash.Hash, limit uint32) []*TxQueueMeta {
	txMetas := mq.inner.getPrioritizedBatch(offset, limit)
	var txs []*TxQueueMeta
	for _, txMeta := range txMetas {
		txs = append(txs, &txMeta.TxQueueMeta)
	}
	return txs
}

func (mq *mainQueue) TakeAll() []*TxQueueMeta {
	txMetas := mq.inner.getAll()
	mq.inner.clear()
	var txs []*TxQueueMeta
	for _, txMeta := range txMetas {
		txs = append(txs, &txMeta.TxQueueMeta)
	}
	return txs
}

func (mq *mainQueue) OfferChecked(tx *TxQueueMeta, meta *protocol.CheckTxMetadata) error {
	txMeta := newTransaction(*tx)
	txMeta.setChecked(meta)

	return mq.inner.add(txMeta)
}

func (mq *mainQueue) GetTxsToPublish() []*TxQueueMeta {
	txMetas := mq.inner.getAll()
	var txs []*TxQueueMeta
	for _, txMeta := range txMetas {
		txs = append(txs, &txMeta.TxQueueMeta)
	}
	return txs
}
