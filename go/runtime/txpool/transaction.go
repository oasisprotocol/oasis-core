package txpool

import (
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// PendingCheckTransaction is a transaction pending checks.
type PendingCheckTransaction struct {
	*TxQueueMeta

	// local indicates whether the transaction came from our own node.
	local bool
	// discard indicates whether the transaction should be discarded after validation.
	discard bool
	// checked indicates whether the transaction already passed check.
	checked bool
	// notifyCh is a channel for sending back the transaction check result.
	notifyCh chan *protocol.CheckTxResult
}
