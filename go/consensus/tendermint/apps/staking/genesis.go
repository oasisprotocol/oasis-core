package staking

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func (app *stakingApplication) initParameters(ctx *abci.Context, state *stakingState.MutableState, st *staking.Genesis) error {
	if err := st.Parameters.SanityCheck(); err != nil {
		return fmt.Errorf("staking/tendermint: sanity check failed: %w", err)
	}

	state.SetConsensusParameters(&st.Parameters)
	return nil
}

func (app *stakingApplication) initCommonPool(ctx *abci.Context, st *staking.Genesis, totalSupply *quantity.Quantity) error {
	if !st.CommonPool.IsValid() {
		return errors.New("staking/tendermint: invalid genesis state CommonPool")
	}
	if err := totalSupply.Add(&st.CommonPool); err != nil {
		ctx.Logger().Error("InitChain: failed to add common pool",
			"err", err,
		)
		return errors.Wrap(err, "staking/tendermint: failed to add common pool")
	}

	return nil
}

func (app *stakingApplication) initLedger(ctx *abci.Context, state *stakingState.MutableState, st *staking.Genesis, totalSupply *quantity.Quantity) error {
	type ledgerUpdate struct {
		id      signature.PublicKey
		account *staking.Account
	}

	var ups []ledgerUpdate
	for k, v := range st.Ledger {
		id := k

		if !v.General.Balance.IsValid() {
			ctx.Logger().Error("InitChain: invalid genesis general balance",
				"id", id,
				"general_balance", v.General.Balance,
			)
			return errors.New("staking/tendermint: invalid genesis general balance")
		}
		if !v.Escrow.Active.Balance.IsValid() {
			ctx.Logger().Error("InitChain: invalid genesis active escrow balance",
				"id", id,
				"escrow_balance", v.Escrow.Active.Balance,
			)
			return errors.New("staking/tendermint: invalid genesis active escrow balance")
		}
		if !v.Escrow.Debonding.Balance.IsValid() {
			ctx.Logger().Error("InitChain: invalid genesis debonding escrow balance",
				"id", id,
				"debonding_balance", v.Escrow.Debonding.Balance,
			)
			return errors.New("staking/tendermint: invalid genesis debonding escrow balance")
		}

		ups = append(ups, ledgerUpdate{id, v})
		if err := totalSupply.Add(&v.General.Balance); err != nil {
			ctx.Logger().Error("InitChain: failed to add general balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add general balance")
		}
		if err := totalSupply.Add(&v.Escrow.Active.Balance); err != nil {
			ctx.Logger().Error("InitChain: failed to add active escrow balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add active escrow balance")
		}
		if err := totalSupply.Add(&v.Escrow.Debonding.Balance); err != nil {
			ctx.Logger().Error("InitChain: failed to add debonding escrow balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add debonding escrow balance")
		}
	}
	// Make sure that we apply ledger updates in a canonical order.
	sort.SliceStable(ups, func(i, j int) bool { return bytes.Compare(ups[i].id[:], ups[j].id[:]) < 0 })
	for _, u := range ups {
		state.SetAccount(u.id, u.account)
	}
	return nil
}

func (app *stakingApplication) initTotalSupply(ctx *abci.Context, state *stakingState.MutableState, st *staking.Genesis, totalSupply *quantity.Quantity) {
	if totalSupply.Cmp(&st.TotalSupply) != 0 {
		ctx.Logger().Error("InitChain: total supply mismatch",
			"expected", st.TotalSupply,
			"actual", totalSupply,
		)
	}

	state.SetCommonPool(&st.CommonPool)
	state.SetTotalSupply(totalSupply)
}

func (app *stakingApplication) initDelegations(ctx *abci.Context, state *stakingState.MutableState, st *staking.Genesis) error {
	type delegationUpdate struct {
		escrowID    signature.PublicKey
		delegatorID signature.PublicKey
		delegation  *staking.Delegation
	}
	var dups []delegationUpdate
	for escrowID, delegations := range st.Delegations {
		delegationShares := quantity.NewQuantity()
		for delegatorID, delegation := range delegations {
			if err := delegationShares.Add(&delegation.Shares); err != nil {
				ctx.Logger().Error("InitChain: failed to add delegation shares",
					"err", err,
				)
				return errors.Wrap(err, "staking/tendermint: failed to add delegation shares")
			}
			dups = append(dups, delegationUpdate{escrowID, delegatorID, delegation})
		}

		acc := state.Account(escrowID)
		if acc.Escrow.Active.TotalShares.Cmp(delegationShares) != 0 {
			ctx.Logger().Error("InitChain: total shares mismatch",
				"escrow_id", escrowID,
				"expected", acc.Escrow.Active.TotalShares,
				"actual", delegationShares,
			)
			return errors.New("staking/tendermint: total shares mismatch")
		}
	}
	// Make sure that we apply delegation updates in a canonical order.
	sort.SliceStable(dups, func(i, j int) bool {
		if c := bytes.Compare(dups[i].escrowID[:], dups[j].escrowID[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(dups[i].delegatorID[:], dups[j].delegatorID[:]) < 0
	})
	for _, u := range dups {
		state.SetDelegation(u.delegatorID, u.escrowID, u.delegation)
	}
	return nil
}

func (app *stakingApplication) initDebondingDelegations(ctx *abci.Context, state *stakingState.MutableState, st *staking.Genesis) error {
	type debondingDelegationUpdate struct {
		escrowID    signature.PublicKey
		delegatorID signature.PublicKey
		seq         uint64
		delegation  *staking.DebondingDelegation
	}
	var deups []debondingDelegationUpdate
	for escrowID, delegators := range st.DebondingDelegations {
		debondingShares := quantity.NewQuantity()
		for delegatorID, delegations := range delegators {
			for idx, delegation := range delegations {
				if err := debondingShares.Add(&delegation.Shares); err != nil {
					ctx.Logger().Error("InitChain: failed to add debonding delegation shares",
						"err", err,
					)
					return errors.Wrap(err, "staking/tendermint: failed to add debonding delegation shares")
				}

				deups = append(deups, debondingDelegationUpdate{escrowID, delegatorID, uint64(idx), delegation})
			}
		}

		acc := state.Account(escrowID)
		if acc.Escrow.Debonding.TotalShares.Cmp(debondingShares) != 0 {
			ctx.Logger().Error("InitChain: debonding shares mismatch",
				"escrow_id", escrowID,
				"expected", acc.Escrow.Debonding.TotalShares,
				"actual", debondingShares,
			)
			return errors.New("staking/tendermint: debonding shares mismatch")
		}
	}
	// Make sure that we apply delegation updates in a canonical order.
	sort.SliceStable(deups, func(i, j int) bool {
		if c := bytes.Compare(deups[i].escrowID[:], deups[j].escrowID[:]); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(deups[i].delegatorID[:], deups[j].delegatorID[:]); c != 0 {
			return c < 0
		}
		return deups[i].seq < deups[j].seq
	})
	for _, u := range deups {
		state.SetDebondingDelegation(u.delegatorID, u.escrowID, u.seq, u.delegation)
	}
	return nil
}

// InitChain initializes the chain from genesis.
func (app *stakingApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
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

	if err := app.initLedger(ctx, state, st, &totalSupply); err != nil {
		return err
	}

	app.initTotalSupply(ctx, state, st, &totalSupply)

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
	totalSupply, err := sq.state.TotalSupply()
	if err != nil {
		return nil, err
	}

	commonPool, err := sq.state.CommonPool()
	if err != nil {
		return nil, err
	}

	accounts, err := sq.state.Accounts()
	if err != nil {
		return nil, err
	}
	ledger := make(map[signature.PublicKey]*staking.Account)
	for _, acctID := range accounts {
		acct := sq.state.Account(acctID)
		ledger[acctID] = acct
	}

	delegations, err := sq.state.Delegations()
	if err != nil {
		return nil, err
	}
	debondingDelegations, err := sq.state.DebondingDelegations()
	if err != nil {
		return nil, err
	}

	params, err := sq.state.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	gen := staking.Genesis{
		Parameters:           *params,
		TotalSupply:          *totalSupply,
		CommonPool:           *commonPool,
		Ledger:               ledger,
		Delegations:          delegations,
		DebondingDelegations: debondingDelegations,
	}
	return &gen, nil
}
