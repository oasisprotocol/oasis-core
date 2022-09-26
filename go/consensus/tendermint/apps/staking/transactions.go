package staking

import (
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func isTransferPermitted(params *staking.ConsensusParameters, fromAddr staking.Address) (permitted bool) {
	permitted = true
	if params.DisableTransfers {
		permitted = false
		if params.UndisableTransfersFrom != nil && params.UndisableTransfersFrom[fromAddr] {
			permitted = true
		}
	}
	return
}

func (app *stakingApplication) transfer(ctx *api.Context, state *stakingState.MutableState, xfer *staking.Transfer) (*staking.TransferResult, error) {
	if ctx.IsCheckOnly() {
		return nil, nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpTransfer, params.GasCosts); err != nil {
		return nil, err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil, nil
	}

	// Check if sender provided at least a minimum amount.
	if xfer.Amount.Cmp(&params.MinTransferAmount) < 0 {
		return nil, staking.ErrUnderMinTransferAmount
	}

	fromAddr := ctx.CallerAddress()
	if fromAddr.IsReserved() || !isTransferPermitted(params, fromAddr) {
		return nil, staking.ErrForbidden
	}

	from, err := state.Account(ctx, fromAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account: %w", err)
	}

	if fromAddr.Equal(xfer.To) {
		// Handle transfer to self as just a balance check.
		if from.General.Balance.Cmp(&xfer.Amount) < 0 {
			err = staking.ErrInsufficientBalance
			ctx.Logger().Debug("Transfer: self-transfer greater than balance",
				"err", err,
				"from", fromAddr,
				"to", xfer.To,
				"amount", xfer.Amount,
			)
			return nil, err
		}
	} else {
		// Source and destination MUST be separate accounts with how
		// quantity.Move is implemented.
		var to *staking.Account
		to, err = state.Account(ctx, xfer.To)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch account: %w", err)
		}
		if err = quantity.Move(&to.General.Balance, &from.General.Balance, &xfer.Amount); err != nil {
			ctx.Logger().Debug("Transfer: failed to move balance",
				"err", err,
				"from", fromAddr,
				"to", xfer.To,
				"amount", xfer.Amount,
			)
			return nil, err
		}

		// Check against minimum balance.
		if from.General.Balance.Cmp(&params.MinTransactBalance) < 0 {
			ctx.Logger().Debug("after transfer source account balance too low",
				"account_addr", fromAddr,
				"account_balance", from.General.Balance,
				"min_transact_balance", params.MinTransactBalance,
			)
			return nil, errors.WithContext(staking.ErrBalanceTooLow, "source account")
		}
		if to.General.Balance.Cmp(&params.MinTransactBalance) < 0 {
			ctx.Logger().Debug("after transfer dest account balance too low",
				"account_addr", xfer.To,
				"account_balance", to.General.Balance,
				"min_transact_balance", params.MinTransactBalance,
			)
			return nil, errors.WithContext(staking.ErrBalanceTooLow, "dest account")
		}

		if err = state.SetAccount(ctx, xfer.To, to); err != nil {
			return nil, fmt.Errorf("failed to set account: %w", err)
		}
	}

	if err = state.SetAccount(ctx, fromAddr, from); err != nil {
		return nil, fmt.Errorf("failed to fetch account: %w", err)
	}

	ctx.Logger().Debug("Transfer: executed transfer",
		"from", fromAddr,
		"to", xfer.To,
		"amount", xfer.Amount,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&staking.TransferEvent{
		From:   fromAddr,
		To:     xfer.To,
		Amount: xfer.Amount,
	}))

	return &staking.TransferResult{
		From:   fromAddr,
		To:     xfer.To,
		Amount: xfer.Amount,
	}, nil
}

func (app *stakingApplication) burn(ctx *api.Context, state *stakingState.MutableState, burn *staking.Burn) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpBurn, params.GasCosts); err != nil {
		return err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	// Check if sender provided at least a minimum amount.
	if burn.Amount.Cmp(&params.MinTransferAmount) < 0 {
		return staking.ErrUnderMinTransferAmount
	}

	fromAddr := ctx.CallerAddress()
	if fromAddr.IsReserved() {
		return staking.ErrForbidden
	}

	from, err := state.Account(ctx, fromAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch account: %w", err)
	}

	if err = from.General.Balance.Sub(&burn.Amount); err != nil {
		ctx.Logger().Error("Burn: failed to burn stake",
			"err", err,
			"from", fromAddr,
			"amount", burn.Amount,
		)
		return err
	}

	// Check against minimum balance.
	if from.General.Balance.Cmp(&params.MinTransactBalance) < 0 {
		ctx.Logger().Debug("after burn account balance too low",
			"account_addr", fromAddr,
			"account_balance", from.General.Balance,
			"min_transact_balance", params.MinTransactBalance,
		)
		return staking.ErrBalanceTooLow
	}

	totalSupply, err := state.TotalSupply(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch total supply: %w", err)
	}

	_ = totalSupply.Sub(&burn.Amount)

	if err = state.SetAccount(ctx, fromAddr, from); err != nil {
		return fmt.Errorf("failed to set account: %w", err)
	}
	if err = state.SetTotalSupply(ctx, totalSupply); err != nil {
		return fmt.Errorf("failed to set total supply: %w", err)
	}

	ctx.Logger().Debug("Burn: burnt stake",
		"from", fromAddr,
		"amount", burn.Amount,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&staking.BurnEvent{
		Owner:  fromAddr,
		Amount: burn.Amount,
	}))

	return nil
}

func (app *stakingApplication) addEscrow(ctx *api.Context, state *stakingState.MutableState, escrow *staking.Escrow) (*staking.AddEscrowResult, error) {
	if ctx.IsCheckOnly() {
		return nil, nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpAddEscrow, params.GasCosts); err != nil {
		return nil, err
	}

	// Check if escrow messages are allowed.
	if ctx.IsMessageExecution() && !params.AllowEscrowMessages {
		return nil, staking.ErrForbidden
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil, nil
	}

	// Check if sender provided at least a minimum amount of stake.
	if escrow.Amount.Cmp(&params.MinDelegationAmount) < 0 {
		return nil, staking.ErrUnderMinDelegationAmount
	}

	fromAddr := ctx.CallerAddress()
	if fromAddr.IsReserved() {
		return nil, staking.ErrForbidden
	}

	from, err := state.Account(ctx, fromAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account: %w", err)
	}

	// Fetch escrow account.
	//
	// NOTE: Could be the same account, so make sure to not have two duplicate
	//       copies of it and overwrite it later.
	var to *staking.Account
	if fromAddr.Equal(escrow.Account) {
		to = from
	} else {
		if params.DisableDelegation {
			return nil, staking.ErrForbidden
		}
		to, err = state.Account(ctx, escrow.Account)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch account: %w", err)
		}
	}

	// Fetch delegation.
	delegation, err := state.Delegation(ctx, fromAddr, escrow.Account)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch delegation: %w", err)
	}

	obtainedShares, err := to.Escrow.Active.Deposit(&delegation.Shares, &from.General.Balance, &escrow.Amount)
	if err != nil {
		ctx.Logger().Debug("AddEscrow: failed to escrow stake",
			"err", err,
			"from", fromAddr,
			"to", escrow.Account,
			"amount", escrow.Amount,
		)
		return nil, err
	}

	// Check against minimum balance.
	if from.General.Balance.Cmp(&params.MinTransactBalance) < 0 {
		ctx.Logger().Debug("after add escrow account balance too low",
			"account_addr", fromAddr,
			"account_balance", from.General.Balance,
			"min_transact_balance", params.MinTransactBalance,
		)
		return nil, staking.ErrBalanceTooLow
	}

	// Commit accounts.
	if err = state.SetAccount(ctx, fromAddr, from); err != nil {
		return nil, fmt.Errorf("failed to set account: %w", err)
	}
	if !fromAddr.Equal(escrow.Account) {
		if err = state.SetAccount(ctx, escrow.Account, to); err != nil {
			return nil, fmt.Errorf("failed to set account: %w", err)
		}
	}
	// Commit delegation descriptor.
	if err = state.SetDelegation(ctx, fromAddr, escrow.Account, delegation); err != nil {
		return nil, fmt.Errorf("failed to set delegation: %w", err)
	}

	ctx.Logger().Debug("AddEscrow: escrowed stake",
		"from", fromAddr,
		"to", escrow.Account,
		"amount", escrow.Amount,
		"obtained_shares", obtainedShares,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&staking.AddEscrowEvent{
		Owner:     fromAddr,
		Escrow:    escrow.Account,
		Amount:    escrow.Amount,
		NewShares: *obtainedShares,
	}))

	return &staking.AddEscrowResult{
		Owner:     fromAddr,
		Escrow:    escrow.Account,
		Amount:    escrow.Amount,
		NewShares: *obtainedShares,
	}, nil
}

func (app *stakingApplication) reclaimEscrow(ctx *api.Context, state *stakingState.MutableState, reclaim *staking.ReclaimEscrow) (*staking.ReclaimEscrowResult, error) {
	// No sense if there is nothing to reclaim.
	if reclaim.Shares.IsZero() {
		return nil, staking.ErrInvalidArgument
	}

	if ctx.IsCheckOnly() {
		return nil, nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpReclaimEscrow, params.GasCosts); err != nil {
		return nil, err
	}

	// Check if escrow messages are allowed.
	if ctx.IsMessageExecution() && !params.AllowEscrowMessages {
		return nil, staking.ErrForbidden
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil, nil
	}

	toAddr := ctx.CallerAddress()
	if toAddr.IsReserved() {
		return nil, staking.ErrForbidden
	}

	to, err := state.Account(ctx, toAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account: %w", err)
	}

	// Fetch escrow account.
	//
	// NOTE: Could be the same account, so make sure to not have two duplicate
	//       copies of it and overwrite it later.
	var from *staking.Account
	if toAddr.Equal(reclaim.Account) {
		from = to
	} else {
		if params.DisableDelegation {
			return nil, staking.ErrForbidden
		}
		from, err = state.Account(ctx, reclaim.Account)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch account: %w", err)
		}
	}

	// Fetch delegation.
	delegation, err := state.Delegation(ctx, toAddr, reclaim.Account)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch delegation: %w", err)
	}

	// Fetch debonding interval and current epoch.
	debondingInterval, err := state.DebondingInterval(ctx)
	if err != nil {
		ctx.Logger().Error("ReclaimEscrow: failed to query debonding interval",
			"err", err,
		)
		return nil, err
	}
	epoch, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		return nil, err
	}

	deb := staking.DebondingDelegation{
		DebondEndTime: epoch + debondingInterval,
	}

	var baseUnits quantity.Quantity

	if err = from.Escrow.Active.Withdraw(&baseUnits, &delegation.Shares, &reclaim.Shares); err != nil {
		ctx.Logger().Debug("ReclaimEscrow: failed to redeem escrow shares",
			"err", err,
			"to", toAddr,
			"from", reclaim.Account,
			"shares", reclaim.Shares,
		)
		return nil, err
	}
	stakeAmount := baseUnits.Clone()

	var debondingShares *quantity.Quantity
	if debondingShares, err = from.Escrow.Debonding.Deposit(&deb.Shares, &baseUnits, stakeAmount); err != nil {
		ctx.Logger().Debug("ReclaimEscrow: failed to debond shares",
			"err", err,
			"to", toAddr,
			"from", reclaim.Account,
			"shares", reclaim.Shares,
			"base_units", stakeAmount,
		)
		return nil, err
	}

	if !baseUnits.IsZero() {
		ctx.Logger().Debug("ReclaimEscrow: inconsistency in transferring stake from active escrow to debonding",
			"remaining_base_units", baseUnits,
		)
		return nil, staking.ErrInvalidArgument
	}

	// Include the end time epoch as the disambiguator. If a debonding delegation for the same account
	// and end time already exists, the delegations will be merged.
	if err = state.SetDebondingDelegation(ctx, toAddr, reclaim.Account, deb.DebondEndTime, &deb); err != nil {
		return nil, fmt.Errorf("failed to set debonding delegation: %w", err)
	}

	if err = state.SetDelegation(ctx, toAddr, reclaim.Account, delegation); err != nil {
		return nil, fmt.Errorf("failed to set delegation: %w", err)
	}
	if err = state.SetAccount(ctx, toAddr, to); err != nil {
		return nil, fmt.Errorf("failed to set account: %w", err)
	}
	if !toAddr.Equal(reclaim.Account) {
		if err = state.SetAccount(ctx, reclaim.Account, from); err != nil {
			return nil, fmt.Errorf("failed to set account: %w", err)
		}
	}

	ctx.Logger().Debug("ReclaimEscrow: started debonding stake",
		"from", reclaim.Account,
		"to", toAddr,
		"base_units", stakeAmount,
		"active_shares", reclaim.Shares,
		"debonding_shares", debondingShares,
		"debond_end_time", deb.DebondEndTime,
	)

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&staking.DebondingStartEscrowEvent{
		Owner:           toAddr,
		Escrow:          reclaim.Account,
		Amount:          *stakeAmount,
		ActiveShares:    reclaim.Shares,
		DebondingShares: *debondingShares,
		DebondEndTime:   deb.DebondEndTime,
	}))

	return &staking.ReclaimEscrowResult{
		Owner:           toAddr,
		Escrow:          reclaim.Account,
		Amount:          *stakeAmount,
		DebondingShares: *debondingShares,
		RemainingShares: delegation.Shares,
		DebondEndTime:   deb.DebondEndTime,
	}, nil
}

func (app *stakingApplication) amendCommissionSchedule(
	ctx *api.Context,
	state *stakingState.MutableState,
	amendCommissionSchedule *staking.AmendCommissionSchedule,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpAmendCommissionSchedule, params.GasCosts); err != nil {
		return err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	epoch, err := app.state.GetEpoch(ctx, ctx.BlockHeight()+1)
	if err != nil {
		return err
	}

	fromAddr := ctx.CallerAddress()
	if fromAddr.IsReserved() {
		return staking.ErrForbidden
	}

	from, err := state.Account(ctx, fromAddr)
	if err != nil {
		return fmt.Errorf("failed to fetch account: %w", err)
	}

	if err = from.Escrow.CommissionSchedule.AmendAndPruneAndValidate(&amendCommissionSchedule.Amendment, &params.CommissionScheduleRules, epoch); err != nil {
		ctx.Logger().Debug("AmendCommissionSchedule: amendment not acceptable",
			"err", err,
			"from", fromAddr,
		)
		return err
	}

	if err = state.SetAccount(ctx, fromAddr, from); err != nil {
		return fmt.Errorf("failed to set account: %w", err)
	}

	return nil
}

func (app *stakingApplication) allow(
	ctx *api.Context,
	state *stakingState.MutableState,
	allow *staking.Allow,
) error {
	if ctx.IsCheckOnly() {
		return nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpAllow, params.GasCosts); err != nil {
		return err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil
	}

	// Allowances are disabled in case either max allowances is zero or if transfers are disabled.
	if params.DisableTransfers || params.MaxAllowances == 0 {
		return staking.ErrForbidden
	}

	// Validate addresses -- if either is reserved or both are equal, the method should fail.
	addr := ctx.CallerAddress()
	if addr.IsReserved() || allow.Beneficiary.IsReserved() {
		return staking.ErrForbidden
	}
	if addr.Equal(allow.Beneficiary) {
		return staking.ErrInvalidArgument
	}

	acct, err := state.Account(ctx, addr)
	if err != nil {
		return fmt.Errorf("failed to fetch account: %w", err)
	}

	if acct.General.Allowances == nil {
		acct.General.Allowances = make(map[staking.Address]quantity.Quantity)
	}
	allowance := acct.General.Allowances[allow.Beneficiary]
	var amountChange *quantity.Quantity
	switch allow.Negative {
	case false:
		// Add.
		if err = allowance.Add(&allow.AmountChange); err != nil {
			return fmt.Errorf("failed to add allowance: %w", err)
		}
		amountChange = allow.AmountChange.Clone()
	case true:
		// Subtract.
		if amountChange, err = allowance.SubUpTo(&allow.AmountChange); err != nil {
			return fmt.Errorf("failed to subtract allowance: %w", err)
		}
	}
	if allowance.IsZero() {
		// In case the new allowance is equal to zero, remove it.
		delete(acct.General.Allowances, allow.Beneficiary)
	} else {
		// Otherwise update the allowance.
		acct.General.Allowances[allow.Beneficiary] = allowance
	}

	// If updating allowances would go past the maximum number of allowances, fail.
	if uint32(len(acct.General.Allowances)) > params.MaxAllowances {
		return staking.ErrTooManyAllowances
	}

	if err = state.SetAccount(ctx, addr, acct); err != nil {
		return fmt.Errorf("failed to set account: %w", err)
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&staking.AllowanceChangeEvent{
		Owner:        addr,
		Beneficiary:  allow.Beneficiary,
		Allowance:    allowance,
		Negative:     allow.Negative,
		AmountChange: *amountChange,
	}))

	return nil
}

func (app *stakingApplication) withdraw(
	ctx *api.Context,
	state *stakingState.MutableState,
	withdraw *staking.Withdraw,
) (*staking.WithdrawResult, error) {
	if ctx.IsCheckOnly() {
		return nil, nil
	}

	// Charge gas for this transaction.
	params, err := state.ConsensusParameters(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch consensus parameters: %w", err)
	}
	if err = ctx.Gas().UseGas(1, staking.GasOpWithdraw, params.GasCosts); err != nil {
		return nil, err
	}

	// Return early for simulation as we only need gas accounting.
	if ctx.IsSimulation() {
		return nil, nil
	}

	// Check if sender provided at least a minimum amount.
	if withdraw.Amount.Cmp(&params.MinTransferAmount) < 0 {
		return nil, staking.ErrUnderMinTransferAmount
	}

	// Allowances are disabled in case either max allowances is zero or if transfers are disabled.
	if params.DisableTransfers || params.MaxAllowances == 0 {
		return nil, staking.ErrForbidden
	}

	// Validate addresses -- if either is reserved or both are equal, the method should fail.
	toAddr := ctx.CallerAddress()
	if toAddr.IsReserved() || withdraw.From.IsReserved() {
		return nil, staking.ErrForbidden
	}
	if toAddr.Equal(withdraw.From) {
		return nil, staking.ErrInvalidArgument
	}

	from, err := state.Account(ctx, withdraw.From)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account: %w", err)
	}
	var (
		allowance quantity.Quantity
		ok        bool
	)
	if allowance, ok = from.General.Allowances[toAddr]; !ok {
		// Fail early in case there is no allowance configured.
		return nil, staking.ErrForbidden
	}
	if err = allowance.Sub(&withdraw.Amount); err != nil {
		return nil, staking.ErrForbidden
	}
	if allowance.IsZero() {
		// In case the new allowance is equal to zero, remove it.
		delete(from.General.Allowances, toAddr)
	} else {
		// Otherwise update the allowance.
		from.General.Allowances[toAddr] = allowance
	}

	// NOTE: Accounts cannot be the same as we fail above if this were the case.
	to, err := state.Account(ctx, toAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch account: %w", err)
	}

	if err = quantity.Move(&to.General.Balance, &from.General.Balance, &withdraw.Amount); err != nil {
		return nil, staking.ErrInsufficientBalance
	}

	// Check against minimum balance.
	if from.General.Balance.Cmp(&params.MinTransactBalance) < 0 {
		ctx.Logger().Debug("after withdraw source account balance too low",
			"account_addr", withdraw.From,
			"account_balance", from.General.Balance,
			"min_transact_balance", params.MinTransactBalance,
		)
		return nil, errors.WithContext(staking.ErrBalanceTooLow, "source account")
	}
	if to.General.Balance.Cmp(&params.MinTransactBalance) < 0 {
		ctx.Logger().Debug("after withdraw dest account balance too low",
			"account_addr", toAddr,
			"account_balance", to.General.Balance,
			"min_transact_balance", params.MinTransactBalance,
		)
		return nil, errors.WithContext(staking.ErrBalanceTooLow, "dest account")
	}

	if err = state.SetAccount(ctx, toAddr, to); err != nil {
		return nil, fmt.Errorf("failed to set account: %w", err)
	}
	if err = state.SetAccount(ctx, withdraw.From, from); err != nil {
		return nil, fmt.Errorf("failed to set account: %w", err)
	}

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&staking.TransferEvent{
		From:   withdraw.From,
		To:     toAddr,
		Amount: withdraw.Amount,
	}))

	ctx.EmitEvent(api.NewEventBuilder(app.Name()).TypedAttribute(&staking.AllowanceChangeEvent{
		Owner:        withdraw.From,
		Beneficiary:  toAddr,
		Allowance:    allowance,
		Negative:     true,
		AmountChange: withdraw.Amount,
	}))

	return &staking.WithdrawResult{
		Owner:        withdraw.From,
		Beneficiary:  toAddr,
		Allowance:    allowance,
		AmountChange: withdraw.Amount,
	}, nil
}
