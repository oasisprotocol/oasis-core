// Package staking implements the staking application.
package staking

import (
	"encoding/hex"

	"github.com/pkg/errors"
	"github.com/tendermint/iavl"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	staking "github.com/oasislabs/ekiden/go/staking/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
	"github.com/oasislabs/ekiden/go/tendermint/api"
)

var (
	_ abci.Application = (*stakingApplication)(nil)
)

type stakingApplication struct {
	logger *logging.Logger

	state *abci.ApplicationState

	debugGenesisState *staking.GenesisState
}

func (app *stakingApplication) Name() string {
	return AppName
}

func (app *stakingApplication) TransactionTag() byte {
	return TransactionTag
}

func (app *stakingApplication) Blessed() bool {
	return false
}

func (app *stakingApplication) GetState(height int64) (interface{}, error) {
	return newImmutableState(app.state, height)
}

func (app *stakingApplication) OnRegister(state *abci.ApplicationState, queryRouter abci.QueryRouter) {
	app.state = state

	// Register the query handlers.
	queryRouter.AddRoute(QueryTotalSupply, nil, app.queryTotalSupply)
	queryRouter.AddRoute(QueryAccounts, nil, app.queryAccounts)
	queryRouter.AddRoute(QueryAccountInfo, api.QueryGetByIDRequest{}, app.queryAccountInfo)
	queryRouter.AddRoute(QueryAllowance, QueryAllowanceRequest{}, app.queryAllowance)
}

func (app *stakingApplication) OnCleanup() {
}

func (app *stakingApplication) SetOption(types.RequestSetOption) types.ResponseSetOption {
	return types.ResponseSetOption{}
}

func (app *stakingApplication) CheckTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("CheckTx: failed to unmarshal",
			"err", err,
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "staking: failed to unmarshal tx")
	}

	return app.executeTx(ctx, app.state.CheckTxTree(), request)
}

func (app *stakingApplication) ForeignCheckTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *stakingApplication) InitChain(ctx *abci.Context, request types.RequestInitChain) types.ResponseInitChain {
	var s staking.GenesisState
	if err := abci.UnmarshalGenesisAppState(request, app, &s); err != nil {
		app.logger.Error("InitChain: failed to unmarshal genesis state",
			"err", err,
		)
		panic("staking: invalid genesis state")
	}

	st := &s
	if app.debugGenesisState != nil {
		if len(s.Ledger) > 0 {
			app.logger.Error("InitChain: debug genesis state and actual genesis state provided")
			panic("staking: multiple genesis states specified")
		}
		st = app.debugGenesisState
	}

	var (
		state       = NewMutableState(app.state.DeliverTxTree())
		totalSupply staking.Quantity
	)
	for k, v := range st.Ledger {
		var id signature.PublicKey
		_ = id.UnmarshalBinary(k[:])

		account := &ledgerEntry{
			GeneralBalance: *v,
			// TODO: Extend the genesis state to support importing.
		}

		state.setAccount(id, account)
		if err := totalSupply.Add(&account.GeneralBalance); err != nil {
			app.logger.Error("InitChain: invalid general balance",
				"id",
				"generalBalance", account.GeneralBalance,
			)
		}
	}
	state.setTotalSupply(&totalSupply)

	app.logger.Debug("InitChain: setting total supply",
		"totalSupply", totalSupply,
	)

	return types.ResponseInitChain{}
}

func (app *stakingApplication) BeginBlock(ctx *abci.Context, request types.RequestBeginBlock) {
}

func (app *stakingApplication) DeliverTx(ctx *abci.Context, tx []byte) error {
	request := &Tx{}
	if err := cbor.Unmarshal(tx, request); err != nil {
		app.logger.Error("DeliverTx: failed to unmarshal",
			"err", err,
			"tx", hex.EncodeToString(tx),
		)
		return errors.Wrap(err, "staking: failed to unmarshal tx")
	}

	return app.executeTx(ctx, app.state.DeliverTxTree(), request)
}

func (app *stakingApplication) ForeignDeliverTx(ctx *abci.Context, other abci.Application, tx []byte) error {
	return nil
}

func (app *stakingApplication) EndBlock(request types.RequestEndBlock) types.ResponseEndBlock {
	return types.ResponseEndBlock{}
}

func (app *stakingApplication) FireTimer(ctx *abci.Context, timer *abci.Timer) {
}

func (app *stakingApplication) queryTotalSupply(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.rawTotalSupply()
}

func (app *stakingApplication) queryAccounts(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)
	return state.rawAccounts()
}

func (app *stakingApplication) queryAccountInfo(s, r interface{}) ([]byte, error) {
	request := r.(*api.QueryGetByIDRequest)
	state := s.(*immutableState)

	ent := state.account(request.ID)
	resp := QueryAccountInfoResponse{
		GeneralBalance: ent.GeneralBalance,
		EscrowBalance:  ent.EscrowBalance,
		Nonce:          ent.Nonce,
	}
	return cbor.Marshal(resp), nil
}

func (app *stakingApplication) queryAllowance(s, r interface{}) ([]byte, error) {
	request := r.(*QueryAllowanceRequest)
	state := s.(*immutableState)

	ent := state.account(request.Owner)
	return cbor.Marshal(ent.getAllowance(request.Spender)), nil
}

func (app *stakingApplication) executeTx(ctx *abci.Context, tree *iavl.MutableTree, tx *Tx) error {
	state := NewMutableState(tree)

	if tx.TxTransfer != nil {
		return app.transfer(ctx, state, &tx.TxTransfer.SignedTransfer)
	} else if tx.TxApprove != nil {
		return app.approve(ctx, state, &tx.TxApprove.SignedApproval)
	} else if tx.TxWithdraw != nil {
		return app.withdraw(ctx, state, &tx.TxWithdraw.SignedWithdrawal)
	} else if tx.TxBurn != nil {
		return app.burn(ctx, state, &tx.TxBurn.SignedBurn)
	} else if tx.TxAddEscrow != nil {
		return app.addEscrow(ctx, state, &tx.TxAddEscrow.SignedEscrow)
	} else {
		return staking.ErrInvalidArgument
	}
}

func (app *stakingApplication) transfer(ctx *abci.Context, state *MutableState, signedXfer *staking.SignedTransfer) error {
	var xfer staking.Transfer
	if err := signedXfer.Open(staking.TransferSignatureContext, &xfer); err != nil {
		app.logger.Error("Transfer: invalid signature",
			"signed_xfer", signedXfer,
		)
		return staking.ErrInvalidSignature
	}

	fromID := signedXfer.Signature.PublicKey
	from := state.account(fromID)
	if from.Nonce != xfer.Nonce {
		app.logger.Error("Transfer: invalid account nonce",
			"from", fromID,
			"account_nonce", from.Nonce,
			"xfer_nonce", xfer.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	to := state.account(xfer.To)
	if err := staking.Move(&to.GeneralBalance, &from.GeneralBalance, &xfer.Tokens); err != nil {
		app.logger.Error("Transfer: failed to move balance",
			"err", err,
			"from", fromID,
			"to", xfer.To,
			"amount", xfer.Tokens,
		)
		return err
	}

	from.Nonce++
	state.setAccount(fromID, from)
	state.setAccount(xfer.To, to)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Transfer: executed transfer",
			"from", fromID,
			"to", xfer.To,
			"amount", xfer.Tokens,
		)

		ctx.EmitData(&Output{
			OutputTransfer: &staking.TransferEvent{
				From:   fromID,
				To:     xfer.To,
				Tokens: xfer.Tokens,
			},
		})
	}

	return nil
}

func (app *stakingApplication) approve(ctx *abci.Context, state *MutableState, signedApproval *staking.SignedApproval) error {
	var approval staking.Approval
	if err := signedApproval.Open(staking.ApproveSignatureContext, &approval); err != nil {
		app.logger.Error("Approve: invalid signature",
			"signed_approval", signedApproval,
		)
		return staking.ErrInvalidSignature
	}

	if !approval.Tokens.IsValid() {
		app.logger.Error("Approve: invalid approval quantity",
			"id", signedApproval.Signature.PublicKey,
			"spender", approval.Spender,
			"amount", approval.Tokens,
		)
		return staking.ErrInvalidArgument
	}

	id := signedApproval.Signature.PublicKey
	from := state.account(id)
	if from.Nonce != approval.Nonce {
		app.logger.Error("Approve: invalid account nonce",
			"from", id,
			"account_nonce", from.Nonce,
			"approval_nonce", approval.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	from.Nonce++
	from.setAllowance(approval.Spender, &approval.Tokens)
	state.setAccount(id, from)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Approve: executed approval",
			"from", id,
			"spender", approval.Spender,
			"amount", approval.Tokens,
		)

		ctx.EmitData(&Output{
			OutputApprove: &staking.ApprovalEvent{
				Owner:   id,
				Spender: approval.Spender,
				Tokens:  approval.Tokens,
			},
		})
	}

	return nil
}

func (app *stakingApplication) withdraw(ctx *abci.Context, state *MutableState, signedWithdrawal *staking.SignedWithdrawal) error {
	var withdrawal staking.Withdrawal
	if err := signedWithdrawal.Open(staking.WithdrawSignatureContext, &withdrawal); err != nil {
		app.logger.Error("Withdraw: invalid signature",
			"signed_withdrawal", signedWithdrawal,
		)
		return staking.ErrInvalidSignature
	}

	fromID := withdrawal.From
	from := state.account(fromID)
	if from.Nonce != withdrawal.Nonce {
		app.logger.Error("Withdraw: invalid account nonce",
			"from", fromID,
			"account_nonce", from.Nonce,
			"withdrawal_nonce", withdrawal.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	toID := signedWithdrawal.Signature.PublicKey
	to := state.account(toID)

	// Ensure there is sufficient allowance.
	allowance := from.getAllowance(toID)
	if err := allowance.Sub(&withdrawal.Tokens); err != nil {
		app.logger.Error("Withdraw: insufficent allowance",
			"id", fromID,
			"spender", toID,
			"amount", withdrawal.Tokens,
		)
		return staking.ErrInsufficientAllowance
	}

	if err := staking.Move(&to.GeneralBalance, &from.GeneralBalance, &withdrawal.Tokens); err != nil {
		app.logger.Error("Withdraw: failed to move balance",
			"err", err,
			"from", fromID,
			"to", toID,
			"amount", withdrawal.Tokens,
		)
		return err
	}

	from.Nonce++
	from.setAllowance(toID, allowance)
	state.setAccount(fromID, from)
	state.setAccount(toID, to)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Withdraw: executed withdrawal",
			"from", fromID,
			"to", toID,
			"amount", withdrawal.Tokens,
		)

		ctx.EmitData(&Output{
			OutputTransfer: &staking.TransferEvent{
				From:   fromID,
				To:     toID,
				Tokens: withdrawal.Tokens,
			},
		})
	}

	return nil
}

func (app *stakingApplication) burn(ctx *abci.Context, state *MutableState, signedBurn *staking.SignedBurn) error {
	var burn staking.Burn
	if err := signedBurn.Open(staking.BurnSignatureContext, &burn); err != nil {
		app.logger.Error("Burn: invalid signature",
			"signed_burn", signedBurn,
		)
		return staking.ErrInvalidSignature
	}

	id := signedBurn.Signature.PublicKey
	from := state.account(id)
	if from.Nonce != burn.Nonce {
		app.logger.Error("Burn: invalid account nonce",
			"from", id,
			"account_nonce", from.Nonce,
			"burn_nonce", burn.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	if err := from.GeneralBalance.Sub(&burn.Tokens); err != nil {
		app.logger.Error("Burn: failed to burn tokens",
			"err", err,
			"from", id,
			"amount", burn.Tokens,
		)
		return err
	}

	totalSupply, _ := state.totalSupply()

	from.Nonce++
	_ = totalSupply.Sub(&burn.Tokens)

	state.setAccount(id, from)
	state.setTotalSupply(totalSupply)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("Burn: burnt tokens",
			"from", id,
			"amount", burn.Tokens,
		)

		ctx.EmitData(&Output{
			OutputBurn: &staking.BurnEvent{
				Owner:  id,
				Tokens: burn.Tokens,
			},
		})
	}

	return nil
}

func (app *stakingApplication) addEscrow(ctx *abci.Context, state *MutableState, signedEscrow *staking.SignedEscrow) error {
	var escrow staking.Escrow
	if err := signedEscrow.Open(staking.EscrowSignatureContext, &escrow); err != nil {
		app.logger.Error("AddEscrow: invalid signature",
			"signed_escrow", signedEscrow,
		)
		return staking.ErrInvalidSignature
	}

	id := signedEscrow.Signature.PublicKey
	from := state.account(id)
	if from.Nonce != escrow.Nonce {
		app.logger.Error("AddEscrow: invalid account nonce",
			"from", id,
			"account_nonce", from.Nonce,
			"escrow_nonce", escrow.Nonce,
		)
		return staking.ErrInvalidNonce
	}

	if err := staking.Move(&from.EscrowBalance, &from.GeneralBalance, &escrow.Tokens); err != nil {
		app.logger.Error("AddEscrow: failed to escrow tokens",
			"err", err,
			"from", id,
			"amount", escrow.Tokens,
		)
		return err
	}

	from.Nonce++
	state.setAccount(id, from)

	if !ctx.IsCheckOnly() {
		app.logger.Debug("AddEscrow: escrowed tokens",
			"from", id,
			"amount", escrow.Tokens,
		)

		ctx.EmitData(&Output{
			OutputAddEscrow: &staking.EscrowEvent{
				Owner:  signedEscrow.Signature.PublicKey,
				Tokens: escrow.Tokens,
			},
		})
	}

	return nil
}

// New constructs a new staking application instance.
func New(debugGenesisState *staking.GenesisState) abci.Application {
	return &stakingApplication{
		logger:            logging.GetLogger("tendermint/staking"),
		debugGenesisState: debugGenesisState,
	}
}
