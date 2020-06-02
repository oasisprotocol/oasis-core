package staking

import (
	"context"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func (app *stakingApplication) initParameters(ctx *abciAPI.Context, state *stakingState.MutableState, st *staking.Genesis) error {
	if err := st.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("tendermint/staking: sanity check failed: %w", err)
	}

	if err := state.SetConsensusParameters(ctx, &st.Parameters); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set consensus parameters: %w", err)
	}
	return nil
}

func (app *stakingApplication) initCommonPool(ctx *abciAPI.Context, st *staking.Genesis, totalSupply *quantity.Quantity) error {
	if !st.CommonPool.IsValid() {
		return fmt.Errorf("tendermint/staking: invalid genesis state CommonPool")
	}
	if err := totalSupply.Add(&st.CommonPool); err != nil {
		ctx.Logger().Error("InitChain: failed to add common pool",
			"err", err,
		)
		return fmt.Errorf("tendermint/staking: failed to add common pool: %w", err)
	}

	return nil
}

func (app *stakingApplication) initLastBlockFees(ctx *abciAPI.Context, st *staking.Genesis, totalSupply *quantity.Quantity) error {
	if !st.LastBlockFees.IsValid() {
		return fmt.Errorf("tendermint/staking: invalid genesis state LastBlockFees")
	}
	if err := totalSupply.Add(&st.LastBlockFees); err != nil {
		ctx.Logger().Error("InitChain: failed to add last block fees",
			"err", err,
		)
		return fmt.Errorf("tendermint/staking: failed to add last block fees: %w", err)
	}

	// XXX: Since there would be no LastCommitInfo for the initial block we
	// move the block fees from genesis into the common pool. And set block fees
	// to zero.
	ctx.Logger().Warn("InitChain: moving last block fees into common pool",
		"last_block_fees", st.LastBlockFees,
		"common_pool", st.CommonPool,
	)
	if err := st.CommonPool.Add(&st.LastBlockFees); err != nil {
		return fmt.Errorf("tendermint/staking: failed to add block fees to common pool")
	}
	st.LastBlockFees = *quantity.NewQuantity()
	return nil
}

func (app *stakingApplication) initLedger(
	ctx *abciAPI.Context,
	state *stakingState.MutableState,
	st *staking.Genesis,
	totalSupply *quantity.Quantity,
) error {
	for id, v := range st.Ledger {
		if v == nil {
			return fmt.Errorf("tendermint/staking: genesis ledger account %s is nil", id)
		}
		if !v.General.Balance.IsValid() {
			ctx.Logger().Error("InitChain: invalid genesis general balance",
				"id", id,
				"general_balance", v.General.Balance,
			)
			return fmt.Errorf("tendermint/staking: invalid genesis general balance")
		}
		if !v.Escrow.Active.Balance.IsValid() {
			ctx.Logger().Error("InitChain: invalid genesis active escrow balance",
				"id", id,
				"escrow_balance", v.Escrow.Active.Balance,
			)
			return fmt.Errorf("tendermint/staking: invalid genesis active escrow balance")
		}
		if !v.Escrow.Debonding.Balance.IsValid() {
			ctx.Logger().Error("InitChain: invalid genesis debonding escrow balance",
				"id", id,
				"debonding_balance", v.Escrow.Debonding.Balance,
			)
			return fmt.Errorf("tendermint/staking: invalid genesis debonding escrow balance")
		}

		// Make sure that the stake accumulator is empty as otherwise it could be inconsistent with
		// what is registered in the genesis block.
		if len(v.Escrow.StakeAccumulator.Claims) > 0 {
			ctx.Logger().Error("InitChain: non-empty stake accumulator",
				"id", id,
			)
			return fmt.Errorf("tendermint/staking: non-empty stake accumulator in genesis")
		}

		if err := totalSupply.Add(&v.General.Balance); err != nil {
			ctx.Logger().Error("InitChain: failed to add general balance",
				"err", err,
			)
			return fmt.Errorf("tendermint/staking: failed to add general balance: %w", err)
		}
		if err := totalSupply.Add(&v.Escrow.Active.Balance); err != nil {
			ctx.Logger().Error("InitChain: failed to add active escrow balance",
				"err", err,
			)
			return fmt.Errorf("tendermint/staking: failed to add active escrow balance: %w", err)
		}
		if err := totalSupply.Add(&v.Escrow.Debonding.Balance); err != nil {
			ctx.Logger().Error("InitChain: failed to add debonding escrow balance",
				"err", err,
			)
			return fmt.Errorf("tendermint/staking: failed to add debonding escrow balance: %w", err)
		}

		if err := state.SetAccount(ctx, id, v); err != nil {
			return fmt.Errorf("tendermint/staking: failed to set account: %w", err)
		}
	}
	return nil
}

func (app *stakingApplication) initTotalSupply(
	ctx *abciAPI.Context,
	state *stakingState.MutableState,
	st *staking.Genesis,
	totalSupply *quantity.Quantity,
) error {
	if totalSupply.Cmp(&st.TotalSupply) != 0 {
		ctx.Logger().Error("InitChain: total supply mismatch",
			"expected", st.TotalSupply,
			"actual", totalSupply,
		)
		return fmt.Errorf("tendermint/staking: total supply mismatch (expected: %s actual: %s)", st.TotalSupply, totalSupply)
	}

	if err := state.SetCommonPool(ctx, &st.CommonPool); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set common pool: %w", err)
	}
	if err := state.SetTotalSupply(ctx, totalSupply); err != nil {
		return fmt.Errorf("tendermint/staking: failed to set total supply: %w", err)
	}

	return nil
}

func (app *stakingApplication) initDelegations(ctx *abciAPI.Context, state *stakingState.MutableState, st *staking.Genesis) error {
	for escrowID, delegations := range st.Delegations {
		delegationShares := quantity.NewQuantity()
		for delegatorID, delegation := range delegations {
			if delegation == nil {
				return fmt.Errorf("tendermint/staking: genesis delegation to %s from %s is nil", escrowID, delegatorID)
			}
			if err := delegationShares.Add(&delegation.Shares); err != nil {
				ctx.Logger().Error("InitChain: failed to add delegation shares",
					"err", err,
				)
				return fmt.Errorf("tendermint/staking: failed to add delegation shares: %w", err)
			}
			if err := state.SetDelegation(ctx, delegatorID, escrowID, delegation); err != nil {
				return fmt.Errorf("tendermint/staking: failed to set delegation: %w", err)
			}
		}

		acc, err := state.Account(ctx, escrowID)
		if err != nil {
			return fmt.Errorf("tendermint/staking: failed to fetch account: %w", err)
		}
		if acc.Escrow.Active.TotalShares.Cmp(delegationShares) != 0 {
			ctx.Logger().Error("InitChain: total shares mismatch",
				"escrow_id", escrowID,
				"expected", acc.Escrow.Active.TotalShares,
				"actual", delegationShares,
			)
			return fmt.Errorf("tendermint/staking: total shares mismatch")
		}
	}
	return nil
}

func (app *stakingApplication) initDebondingDelegations(ctx *abciAPI.Context, state *stakingState.MutableState, st *staking.Genesis) error {
	for escrowID, delegators := range st.DebondingDelegations {
		debondingShares := quantity.NewQuantity()
		for delegatorID, delegations := range delegators {
			for idx, delegation := range delegations {
				if delegation == nil {
					return fmt.Errorf("tendermint/staking: genesis debonding delegation to %s from %s index %d is nil", escrowID, delegatorID, idx)
				}
				if err := debondingShares.Add(&delegation.Shares); err != nil {
					ctx.Logger().Error("InitChain: failed to add debonding delegation shares",
						"err", err,
					)
					return fmt.Errorf("tendermint/staking: failed to add debonding delegation shares: %w", err)
				}

				if err := state.SetDebondingDelegation(ctx, delegatorID, escrowID, uint64(idx), delegation); err != nil {
					return fmt.Errorf("tendermint/staking: failed to set debonding delegation: %w", err)
				}
			}
		}

		acc, err := state.Account(ctx, escrowID)
		if err != nil {
			return fmt.Errorf("tendermint/staking: failed to fetch account: %w", err)
		}
		if acc.Escrow.Debonding.TotalShares.Cmp(debondingShares) != 0 {
			ctx.Logger().Error("InitChain: debonding shares mismatch",
				"escrow_id", escrowID,
				"expected", acc.Escrow.Debonding.TotalShares,
				"actual", debondingShares,
			)
			return fmt.Errorf("tendermint/staking: debonding shares mismatch")
		}
	}
	return nil
}

// InitChain initializes the chain from genesis.
func (app *stakingApplication) InitChain(ctx *abciAPI.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := &doc.Staking

	var (
		state       = stakingState.NewMutableState(ctx.State())
		totalSupply quantity.Quantity
	)

	if err := app.initParameters(ctx, state, st); err != nil {
		return err
	}

	if err := app.initCommonPool(ctx, st, &totalSupply); err != nil {
		return err
	}

	if err := app.initLastBlockFees(ctx, st, &totalSupply); err != nil {
		return err
	}

	if err := app.initLedger(ctx, state, st, &totalSupply); err != nil {
		return err
	}

	if err := app.initTotalSupply(ctx, state, st, &totalSupply); err != nil {
		return err
	}

	if err := app.initDelegations(ctx, state, st); err != nil {
		return err
	}

	if err := app.initDebondingDelegations(ctx, state, st); err != nil {
		return err
	}

	ctx.Logger().Debug("InitChain: allocations complete",
		"common_pool", st.CommonPool,
		"total_supply", totalSupply,
	)

	return nil
}

// Genesis exports current state in genesis format.
func (sq *stakingQuerier) Genesis(ctx context.Context) (*staking.Genesis, error) {
	totalSupply, err := sq.state.TotalSupply(ctx)
	if err != nil {
		return nil, err
	}

	commonPool, err := sq.state.CommonPool(ctx)
	if err != nil {
		return nil, err
	}

	lastBlockFees, err := sq.state.LastBlockFees(ctx)
	if err != nil {
		return nil, err
	}

	accounts, err := sq.state.Accounts(ctx)
	if err != nil {
		return nil, err
	}
	ledger := make(map[signature.PublicKey]*staking.Account)
	for _, acctID := range accounts {
		var acct *staking.Account
		acct, err = sq.state.Account(ctx, acctID)
		if err != nil {
			return nil, fmt.Errorf("tendermint/staking: failed to fetch account: %w", err)
		}
		// Make sure that export resets the stake accumulator state as that should be re-initialized
		// during genesis (a genesis document with non-empty stake accumulator is invalid).
		acct.Escrow.StakeAccumulator = staking.StakeAccumulator{}
		ledger[acctID] = acct
	}

	delegations, err := sq.state.Delegations(ctx)
	if err != nil {
		return nil, err
	}
	debondingDelegations, err := sq.state.DebondingDelegations(ctx)
	if err != nil {
		return nil, err
	}

	params, err := sq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	gen := staking.Genesis{
		Parameters:           *params,
		TotalSupply:          *totalSupply,
		CommonPool:           *commonPool,
		LastBlockFees:        *lastBlockFees,
		Ledger:               ledger,
		Delegations:          delegations,
		DebondingDelegations: debondingDelegations,
	}
	return &gen, nil
}
