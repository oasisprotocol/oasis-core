package txpool

import (
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

var (
	_ UsableTransactionSource        = (*mainQueue)(nil)
	_ RecheckableTransactionStore    = (*mainQueue)(nil)
	_ RepublishableTransactionSource = (*mainQueue)(nil)
)

// Transaction is a transaction in the transaction pool.
type Transaction struct {
	// tx represents the raw binary transaction data.
	tx []byte

	// time is the timestamp when the transaction was first seen.
	time time.Time
	// hash is the cached transaction hash.
	hash hash.Hash

	// priority defines the transaction's priority as specified by the runtime.
	priority uint64

	// sender is a unique transaction sender identifier as specified by the runtime.
	sender string
	// senderSeq is a per-sender sequence number as specified by the runtime.
	senderSeq uint64
}

func newTransaction(tx []byte) *Transaction {
	return &Transaction{
		tx:   tx,
		time: time.Now(),
		hash: hash.NewFromBytes(tx),
	}
}

// String returns a string representation of a transaction.
func (tx *Transaction) String() string {
	return fmt.Sprintf("Transaction{hash: %s, time: %s, priority: %d}", tx.hash, tx.time, tx.priority)
}

// Raw returns the raw transaction data.
func (tx *Transaction) Raw() []byte {
	return tx.tx
}

// Size returns the size (in bytes) of the raw transaction data.
func (tx *Transaction) Size() int {
	return len(tx.tx)
}

// Hash returns the hash of the transaction binary data.
func (tx *Transaction) Hash() hash.Hash {
	return tx.hash
}

// Time returns the time the transaction was first seen.
func (tx *Transaction) Time() time.Time {
	return tx.time
}

// Priority returns the transaction priority.
func (tx *Transaction) Priority() uint64 {
	return tx.priority
}

// Sender returns the transaction sender.
func (tx *Transaction) Sender() string {
	return tx.sender
}

// SenderSeq returns the per-sender sequence number.
func (tx *Transaction) SenderSeq() uint64 {
	return tx.senderSeq
}

// setChecked populates transaction data retrieved from checks.
func (tx *Transaction) setChecked(meta *protocol.CheckTxMetadata) {
	if meta != nil {
		tx.priority = meta.Priority
		tx.sender = string(meta.Sender)
		tx.senderSeq = meta.SenderSeq
	}

	// If the sender is empty (e.g. because the runtime does not support specifying a sender), we
	// treat each transaction as having a unique sender. This is to allow backwards compatibility.
	if len(tx.sender) == 0 {
		tx.sender = string(tx.hash[:])
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
		txs = append(txs, &TxQueueMeta{
			Raw:  txMeta.tx,
			Hash: txMeta.hash,
		})
	}
	return txs
}

func (mq *mainQueue) GetTxByHash(h hash.Hash) *TxQueueMeta {
	txMetas, _ := mq.inner.getKnownBatch([]hash.Hash{h})
	if txMetas[0] == nil {
		return nil
	}
	return &TxQueueMeta{
		Raw:  txMetas[0].tx,
		Hash: txMetas[0].hash,
	}
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
	txMeta := newTransaction(tx.Raw)
	txMeta.setChecked(meta)

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
