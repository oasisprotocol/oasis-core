package staking

import (
	staking "github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

const (
	// TransactionTag is a unique byte used to identify transactions
	// for the staking application.
	TransactionTag byte = 0x05

	// AppName is the ABCI application name.
	AppName string = "100_staking"
)

var (
	// TagTakeEscrow is an ABCI transaction tag for TakeEscrow calls
	// (value is an app.TakeEscrowEvent).
	TagTakeEscrow = []byte("staking.take_escrow")

	// TagReclaimEscrow is an ABCI trasnsaction tag for ReclaimEscrow
	// calls (value is an app.ReclaimEscrowEvent).
	TagReclaimEscrow = []byte("staking.reclaim_escrow")

	// TagTransfer is an ABCI transaction tag for Transfers that happen
	// in a non-staking app (value is an app.TransferEvent).
	TagTransfer = []byte("staking.transfer")

	// QueryApp is a query for filtering transactions processed by
	// the staking application.
	QueryApp = api.QueryForEvent([]byte(AppName), api.TagAppNameValue)
)

const (
	// QueryTotalSupply is the path for a TotalSupply query.
	QueryTotalSupply = AppName + "/total_supply"

	// QueryCommonPool is the path for a CommonPool query.
	QueryCommonPool = AppName + "/common_pool"

	// QueryThresholds is the path for a Thresholds query.
	QueryThresholds = AppName + "/thresholds"

	// QueryAccounts is the path for an Accounts query.
	QueryAccounts = AppName + "/accounts"

	// QueryAccountInfo is the path for an AccountInfo query.
	QueryAccountInfo = AppName + "/account_info"

	// QueryDebondingInterval is the path for a DebondingInterval query.
	QueryDebondingInterval = AppName + "/debonding_interval"

	// QueryGenesis is the path for a Genesis query.
	QueryGenesis = AppName + "/genesis"
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
	OutputTransfer      *staking.TransferEvent      `json:"Transfer,omitempty"`
	OutputBurn          *staking.BurnEvent          `json:"Burn,omitempty"`
	OutputAddEscrow     *staking.EscrowEvent        `json:"AddEscrow,omitempty"`
	OutputReclaimEscrow *staking.ReclaimEscrowEvent `json:"ReclaimEscrow,omitempty"`
}

// QueryAccountInfoResponse is a response to QueryAccountInfo.
type QueryAccountInfoResponse struct {
	GeneralBalance  staking.Quantity `json:"general_balance"`
	EscrowBalance   staking.Quantity `json:"escrow_balance"`
	DebondStartTime uint64           `json:"debond_start_time"`
	Nonce           uint64           `json:"nonce"`
}
