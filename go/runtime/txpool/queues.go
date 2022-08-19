package txpool

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// TxQueueMeta stores some queuing-related metadata alongside a raw transaction.
type TxQueueMeta struct {
	raw  []byte
	hash hash.Hash
	// firstSeen is the timestamp when the transaction was first seen.
	// We populate this in `submitTx`. Other forms of ingress (namely loading from roothash incoming messages and
	// receiving from txSync) leave this in its default value. Transactions from those sources, however, only move
	// through a limited area in the tx pool.
	firstSeen time.Time
}

// Raw returns the raw transaction data.
func (t *TxQueueMeta) Raw() []byte {
	return t.raw
}

// Size returns the size (in bytes) of the raw transaction data.
func (t *TxQueueMeta) Size() int {
	return len(t.Raw())
}

// Hash returns the hash of the transaction binary data.
func (t *TxQueueMeta) Hash() hash.Hash {
	return t.hash
}

// FirstSeen returns the time the transaction was first seen.
func (t *TxQueueMeta) FirstSeen() time.Time {
	return t.firstSeen
}

// UsableTransactionSource is a place to retrieve txs that are "good enough." "Good enough" variously means CheckTx'd,
// came from roothash incoming message, or came from our own node.
type UsableTransactionSource interface {
	// GetSchedulingSuggestion returns some number of txs to give to the scheduler as part of the initial
	// batch.
	GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta
	// GetTxByHash returns the specific tx, if it is in this queue. The bool is like `value, ok := txMap[key]`. Used
	// for resolving a batch from hashes and serving txSync.
	GetTxByHash(h hash.Hash) *TxQueueMeta
	// HandleTxsUsed is a callback to indicate that the scheduler is done with a set of txs, by hash. For most
	// implementations, remove it from internal storage.
	HandleTxsUsed(hashes []hash.Hash)
}

// RecheckableTransactionStore provides methods for rechecking.
type RecheckableTransactionStore interface {
	// TakeAll removes all txs and returns them.
	TakeAll() []*TxQueueMeta
	// OfferChecked adds a tx that is checked.
	OfferChecked(tx *TxQueueMeta, meta *protocol.CheckTxMetadata) error
}

// RepublishableTransactionSource is a place to get txs that we want to push.
type RepublishableTransactionSource interface {
	// GetTxsToPublish gets txs that this queue wants to publish.
	GetTxsToPublish() []*TxQueueMeta
}
