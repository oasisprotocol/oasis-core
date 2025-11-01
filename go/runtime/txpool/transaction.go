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
	// local indicates whether the transaction came from our own node.
	local bool
	// discard indicates whether the transaction should be discarded after validation.
	discard bool
	// notifyCh is a channel for sending back the transaction check result.
	notifyCh chan *protocol.CheckTxResult
}
