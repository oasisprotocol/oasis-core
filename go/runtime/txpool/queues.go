package txpool

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

type TxQueueMeta struct {
	Raw  []byte
	Hash hash.Hash
}

// UsableTransactionSource is a place to retrieve txs that are "good enough." "Good enough" variously means CheckTx'd,
// came from roothash incoming message, or came from our own node.
type UsableTransactionSource interface {
	// GetSchedulingSuggestion returns some number of txs to give to the scheduler as part of the initial
	// batch.
	GetSchedulingSuggestion(countHint uint32) []*TxQueueMeta
	// GetTxByHash returns the specific tx, if it is in this queue. The bool is like `value, ok := txMap[key]`. Used
	// for resolving a batch from hashes and serving txSync.
	GetTxByHash(h hash.Hash) (*TxQueueMeta, bool)
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
