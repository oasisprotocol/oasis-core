package txpool

import (
	"fmt"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
)

type txStatus uint8

const (
	txStatusPendingCheck = iota
	txStatusChecked
)

// Transaction is a transaction in the transaction pool.
type Transaction struct {
	// tx represents the raw binary transaction data.
	tx []byte

	// status is the transaction status.
	status txStatus
	// time is the timestamp when the transaction was first seen.
	time time.Time
	// hash is the cached transaction hash.
	hash hash.Hash

	// priority defines the transaction's priority as specified by the runtime
	// in the CheckTx response.
	priority uint64
	// weights defines the transaction's runtime specific weights as specified
	// in the CheckTx response.
	weights map[transaction.Weight]uint64
}

func newTransaction(tx []byte, status txStatus) *Transaction {
	return &Transaction{
		tx:     tx,
		status: status,
		time:   time.Now(),
		hash:   hash.NewFromBytes(tx),
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

// setChecked populates transaction data retrieved from checks.
func (tx *Transaction) setChecked(meta *protocol.CheckTxMetadata) {
	tx.status = txStatusChecked

	if meta != nil {
		tx.priority = meta.Priority
		// TODO: Remove weights in favor of mandating runtime schedule control.
		tx.weights = meta.Weights
	}

	if tx.weights == nil {
		tx.weights = make(map[transaction.Weight]uint64)
	}
	tx.weights[transaction.WeightSizeBytes] = uint64(tx.Size())
	tx.weights[transaction.WeightCount] = 1
}

// txCheckFlags are the flags describing how transaction should be checked.
type txCheckFlags uint8

const (
	// txCheckLocal is a flag indicating that the transaction was obtained from a local client.
	txCheckLocal = (1 << 0)
	// txCheckDiscard is a flag indicating that the transaction should be discarded after checks.
	txCheckDiscard = (1 << 1)
)

func (f txCheckFlags) isLocal() bool {
	return (f & txCheckLocal) != 0
}

func (f txCheckFlags) isDiscard() bool {
	return (f & txCheckDiscard) != 0
}

// PendingCheckTransaction is a transaction pending checks.
type PendingCheckTransaction struct {
	*Transaction

	// flags are the transaction check flags.
	flags txCheckFlags
	// notifyCh is a channel for sending back the transaction check result.
	notifyCh chan *protocol.CheckTxResult
}

func (pct *PendingCheckTransaction) isRecheck() bool {
	// If transaction has already been checked then the fact that it is wrapped in a pending check
	// transaction again means that this is a re-check.
	return pct.status == txStatusChecked
}
