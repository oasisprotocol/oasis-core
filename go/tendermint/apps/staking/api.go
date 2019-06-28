package staking

import (
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
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

	// TagReleaseEscrow is an ABCI trasnsaction tag for ReleaseEscrow
	// calls (value is an app.ReleaseEscrowEvent).
	TagReleaseEscrow = []byte("staking.release_escrow")

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

	// QueryAccounts is the path for an Accounts query.
	QueryAccounts = AppName + "/accounts"

	// QueryAccountInfo is the path for an AccountInfo query.
	QueryAccountInfo = AppName + "/account_info"

	// QueryAllowance is the path for an Allowance query.
	QueryAllowance = AppName + "/allowance"
)

// Tx is a transaction to be accepted by the staking app.
type Tx struct {
	_struct struct{} `codec:",omitempty"` // nolint

	*TxTransfer  `codec:"Transfer"`
	*TxApprove   `codec:"Approve"`
	*TxWithdraw  `codec:"Withdraw"`
	*TxBurn      `codec:"Burn"`
	*TxAddEscrow `codec:"AddEscrow"`
}

// TxTransfer is a transaction for a transfer.
type TxTransfer struct {
	SignedTransfer staking.SignedTransfer
}

// TxApprove is a transaction for an Approve.
type TxApprove struct {
	SignedApproval staking.SignedApproval
}

// TxWithdraw is a transaction for a Withdraw.
type TxWithdraw struct {
	SignedWithdrawal staking.SignedWithdrawal
}

// TxBurn is a transaction for a Burn.
type TxBurn struct {
	SignedBurn staking.SignedBurn
}

// TxAddEscrow is a transaction for an AddEscrow.
type TxAddEscrow struct {
	SignedEscrow staking.SignedEscrow
}

// Output is an output of a staking transaction.
type Output struct {
	_struct struct{} `codec:",omitemtpy"` // nolint

	OutputTransfer  *staking.TransferEvent `codec:"Transfer"`
	OutputApprove   *staking.ApprovalEvent `codec:"Approve"`
	OutputBurn      *staking.BurnEvent     `codec:"Burn"`
	OutputAddEscrow *staking.EscrowEvent   `codec:"AddEscrow"`
}

// QueryAccountInfoResponse is a response to QueryAccountInfo.
type QueryAccountInfoResponse struct {
	GeneralBalance staking.Quantity `codec:"general_balance"`
	EscrowBalance  staking.Quantity `codec:"escrow_balance"`
	Nonce          uint64           `codec:"nonce"`
}

// QueryAllowanceRequest is a request to QueryAllowance.
type QueryAllowanceRequest struct {
	Owner   signature.PublicKey `codec:"owner"`
	Spender signature.PublicKey `codec:"spender"`
}
