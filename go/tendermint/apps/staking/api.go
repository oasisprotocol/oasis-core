package staking

import (
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the staking application.
	TransactionTag byte = 0x05

	// AppName is the ABCI application name.
	AppName string = "100_staking"
)

var (
	// TagUpdate is an ABCI transaction tag for marking transactions
	// which have been processed by staking (value is TagUpdateValue).
	TagUpdate = []byte("staking.update")
	// TagUpdateValue is the only allowed value for TagUpdate.
	TagUpdateValue = []byte{0x01}

	// TagTakeEscrow is an ABCI transaction tag for TakeEscrow calls
	// (value is an app.TakeEscrowEvent).
	TagTakeEscrow = []byte("staking.take_escrow")

	// TagReclaimEscrow is an ABCI trasnsaction tag for ReclaimEscrow
	// calls (value is an app.ReclaimEscrowEvent).
	TagReclaimEscrow = []byte("staking.reclaim_escrow")

	// TagTransfer is an ABCI transaction tag for Transfers that happen
	// in a non-staking app (value is an app.TransferEvent).
	TagTransfer = []byte("staking.transfer")

	// QueryUpdate is a query for filtering transactions/blocks where staking
	// application state has been updated. This is required as state can
	// change as part of timers firing.
	QueryUpdate = api.QueryForEvent(TagUpdate, TagUpdateValue)
)

// Tx is a transaction to be accepted by the staking app.
type Tx struct {
	*TxTransfer      `json:"Transfer,omitempty"`
	*TxBurn          `json:"Burn,omitempty"`
	*TxAddEscrow     `json:"AddEscrow,omitempty"`
	*TxReclaimEscrow `json:"ReclaimEscrow,omitempty"`
}

// TxTransfer is a transaction for a transfer.
type TxTransfer struct {
	SignedTransfer staking.SignedTransfer
}

// TxBurn is a transaction for a Burn.
type TxBurn struct {
	SignedBurn staking.SignedBurn
}

// TxAddEscrow is a transaction for an AddEscrow.
type TxAddEscrow struct {
	SignedEscrow staking.SignedEscrow
}

// TxReclaimEscrow is a transaction for a ReclaimEscrow.
type TxReclaimEscrow struct {
	SignedReclaimEscrow staking.SignedReclaimEscrow
}

// Output is an output of a staking transaction.
type Output struct {
	OutputTransfer  *staking.TransferEvent `json:"Transfer,omitempty"`
	OutputBurn      *staking.BurnEvent     `json:"Burn,omitempty"`
	OutputAddEscrow *staking.EscrowEvent   `json:"AddEscrow,omitempty"`
}
