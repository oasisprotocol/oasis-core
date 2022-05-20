package txpool

import (
	"time"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

// UsableTransactionSource is a place to retrieve txs that are "good enough." "Good enough" variously means CheckTx'd,
// came from roothash incoming message, or came from our own node.
type UsableTransactionSource interface {
	// GetSchedulingSuggestion returns some number of txs to give to the scheduler as part of the initial
	// batch.
	GetSchedulingSuggestion() [][]byte
	// GetTxByHash returns the specific tx, if it is in this queue. The bool is like `value, ok := txMap[key]`. Used
	// for resolving a batch from hashes and serving txSync.
	GetTxByHash(h hash.Hash) ([]byte, bool)
	// HandleTxsUsed is a callback to indicate that the scheduler is done with a set of txs, by hash. For most
	// implementations, remove it from internal storage.
	HandleTxsUsed(hashes []hash.Hash)
}

// RecheckableTransactionStore provides methods for rechecking.
type RecheckableTransactionStore interface {
	// TakeAll removes all txs and returns them.
	TakeAll() [][]byte
	// OfferChecked adds a tx that is checked.
	OfferChecked(tx []byte)
}

// RepublishableTransactionSource is a place to get txs that we want to push.
type RepublishableTransactionSource interface {
	// GetTxsToPublish gets txs that this queue wants to publish between last call and now given, as well as next time
	// that it wants to publish any txs.
	GetTxsToPublish(now time.Time) ([][]byte, time.Time)
}
