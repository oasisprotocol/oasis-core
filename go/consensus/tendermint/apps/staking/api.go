package staking

import (
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the staking application.
	TransactionTag byte = 0x05
)

var (
	// AppName is the ABCI application name.
	AppName = stakingState.AppName

	//EventType is the ABCI event type for staking events.
	EventType = api.EventTypeForApp(AppName)

	// QueryApp is a query for filtering events processed by the
	// staking application.
	QueryApp = api.QueryForApp(AppName)

	// KeyTakeEscrow is an ABCI event attribute key for TakeEscrow calls
	// (value is an app.TakeEscrowEvent).
	KeyTakeEscrow = stakingState.KeyTakeEscrow

	// KeyReclaimEscrow is an ABCI event attribute key for ReclaimEscrow
	// calls (value is an app.ReclaimEscrowEvent).
	KeyReclaimEscrow = []byte("reclaim_escrow")

	// KeyTransfer is an ABCI event attribute key for Transfers (value is
	// an app.TransferEvent).
	KeyTransfer = stakingState.KeyTransfer

	// KeyBurn is an ABCI event attribute key for Burn calls (value is
	// an app.BurnEvent).
	KeyBurn = []byte("burn")

	// KeyAddEscrow is an ABCI event attribute key for AddEscrow calls
	// (value is an app.EscrowEvent).
	KeyAddEscrow = []byte("add_escrow")
)

// Tx is a transaction to be accepted by the staking app.
type Tx struct {
	*TxTransfer                `json:"Transfer,omitempty"`
	*TxBurn                    `json:"Burn,omitempty"`
	*TxAddEscrow               `json:"AddEscrow,omitempty"`
	*TxReclaimEscrow           `json:"ReclaimEscrow,omitempty"`
	*TxAmendCommissionSchedule `json:"AmendCommissionSchedule,omitempty"`
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

// TxAmendCommissionSchedule is a transaction for an AmendCommissionSchedule
type TxAmendCommissionSchedule struct {
	SignedAmendCommissionSchedule staking.SignedAmendCommissionSchedule
}
