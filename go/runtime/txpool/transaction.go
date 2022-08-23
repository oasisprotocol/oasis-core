package txpool

import (
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
)

// txCheckFlags are the flags describing how a transaction should be checked.
type txCheckFlags uint8

const (
	// txCheckRecheck is a flag indicating that the transaction already passed checking earlier.
	txCheckRecheck = 1 << 0
)

func (f txCheckFlags) isRecheck() bool {
	return (f * txCheckRecheck) != 0
}

// PendingCheckTransaction is a transaction pending checks.
type PendingCheckTransaction struct {
	*TxQueueMeta

	// flags are the transaction check flags.
	flags txCheckFlags
	// dstQueue is where to offer the tx after checking, or nil to discard.
	dstQueue RecheckableTransactionStore
	// notifyCh is a channel for sending back the transaction check result.
	notifyCh chan *protocol.CheckTxResult
}
