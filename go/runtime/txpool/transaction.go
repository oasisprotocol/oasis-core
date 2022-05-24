package txpool

import (
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// todo: move to main_queue.go
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

// todo: move this be part of OfferChecked
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

// todo: move to check_queue.go
// PendingCheckTransaction is a transaction pending checks.
type PendingCheckTransaction struct {
	tx []byte

	// dstQueue is where to offer the tx after checking, or nil to discard
	dstQueue RecheckableTransactionStore
	// notifyCh is a channel for sending back the transaction check result.
	notifyCh chan *protocol.CheckTxResult
}
