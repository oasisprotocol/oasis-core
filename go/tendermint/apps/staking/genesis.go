package staking

import (
	"bytes"
	"context"
	"sort"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	stakingState "github.com/oasislabs/oasis-core/go/tendermint/apps/staking/state"
)

func (app *stakingApplication) initParameters(state *stakingState.MutableState, st *staking.Genesis) {
	state.SetDebondingInterval(uint64(st.Parameters.DebondingInterval))
	state.SetRewardSchedule(st.Parameters.RewardSchedule)
	state.SetAcceptableTransferPeers(st.Parameters.AcceptableTransferPeers)
	state.SetSlashing(st.Parameters.Slashing)
}

func (app *stakingApplication) initThresholds(state *stakingState.MutableState, st *staking.Genesis) error {
	type thresholdUpdate struct {
		k staking.ThresholdKind
		v quantity.Quantity
	}

	if st.Parameters.Thresholds != nil {
		var ups []thresholdUpdate
		for k, v := range st.Parameters.Thresholds {
			if !v.IsValid() {
				app.logger.Error("InitChain: invalid threshold",
					"threshold", k,
					"quantity", v,
				)
				return errors.New("staking/tendermint: invalid genesis threshold")
			}
			ups = append(ups, thresholdUpdate{k, v})
		}

		// Make sure that we apply threshold updates in a canonical order.
		sort.SliceStable(ups, func(i, j int) bool { return ups[i].k < ups[j].k })
		for _, u := range ups {
			state.SetThreshold(u.k, &u.v)
		}
	}

	return nil
}

func (app *stakingApplication) initCommonPool(st *staking.Genesis, totalSupply *quantity.Quantity) error {
	if !st.CommonPool.IsValid() {
		return errors.New("staking/tendermint: invalid genesis state CommonPool")
	}
	if err := totalSupply.Add(&st.CommonPool); err != nil {
		app.logger.Error("InitChain: failed to add common pool",
			"err", err,
		)
		return errors.Wrap(err, "staking/tendermint: failed to add common pool")
	}

	return nil
}

func (app *stakingApplication) initLedger(state *stakingState.MutableState, st *staking.Genesis, totalSupply *quantity.Quantity) error {
	type ledgerUpdate struct {
		id      signature.PublicKey
		account *staking.Account
	}

	var ups []ledgerUpdate
	for k, v := range st.Ledger {
		var id signature.PublicKey
		id.FromMapKey(k)

		if !v.General.Balance.IsValid() {
			app.logger.Error("InitChain: invalid genesis general balance",
				"id", id,
				"general_balance", v.General.Balance,
			)
			return errors.New("staking/tendermint: invalid genesis general balance")
		}
		if !v.Escrow.Active.Balance.IsValid() {
			app.logger.Error("InitChain: invalid genesis active escrow balance",
				"id", id,
				"escrow_balance", v.Escrow.Active.Balance,
			)
			return errors.New("staking/tendermint: invalid genesis active escrow balance")
		}
		if !v.Escrow.Debonding.Balance.IsValid() {
			app.logger.Error("InitChain: invalid genesis debonding escrow balance",
				"id", id,
				"debonding_balance", v.Escrow.Debonding.Balance,
			)
			return errors.New("staking/tendermint: invalid genesis debonding escrow balance")
		}

		ups = append(ups, ledgerUpdate{id, v})
		if err := totalSupply.Add(&v.General.Balance); err != nil {
			app.logger.Error("InitChain: failed to add general balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add general balance")
		}
		if err := totalSupply.Add(&v.Escrow.Active.Balance); err != nil {
			app.logger.Error("InitChain: failed to add active escrow balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add active escrow balance")
		}
		if err := totalSupply.Add(&v.Escrow.Debonding.Balance); err != nil {
			app.logger.Error("InitChain: failed to add debonding escrow balance",
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

func (app *stakingApplication) initTotalSupply(state *stakingState.MutableState, st *staking.Genesis, totalSupply *quantity.Quantity) {
	if totalSupply.Cmp(&st.TotalSupply) != 0 {
		app.logger.Error("InitChain: total supply mismatch",
			"expected", st.TotalSupply,
			"actual", totalSupply,
		)
	}

	state.SetCommonPool(&st.CommonPool)
	state.SetTotalSupply(totalSupply)
}

func (app *stakingApplication) initDelegations(state *stakingState.MutableState, st *staking.Genesis) error {
	type delegationUpdate struct {
		escrowID    signature.PublicKey
		delegatorID signature.PublicKey
		delegation  *staking.Delegation
	}
	var dups []delegationUpdate
	for keyEscrowID, delegations := range st.Delegations {
		var escrowID signature.PublicKey
		escrowID.FromMapKey(keyEscrowID)

		delegationShares := quantity.NewQuantity()
		for keyDelegatorID, delegation := range delegations {
			var delegatorID signature.PublicKey
			delegatorID.FromMapKey(keyDelegatorID)

			if err := delegationShares.Add(&delegation.Shares); err != nil {
				app.logger.Error("InitChain: failed to add delegation shares",
					"err", err,
				)
				return errors.Wrap(err, "staking/tendermint: failed to add delegation shares")
			}
			dups = append(dups, delegationUpdate{escrowID, delegatorID, delegation})
		}

		acc := state.Account(escrowID)
		if acc.Escrow.Active.TotalShares.Cmp(delegationShares) != 0 {
			app.logger.Error("InitChain: total shares mismatch",
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

func (app *stakingApplication) initDebondingDelegations(state *stakingState.MutableState, st *staking.Genesis) error {
	type debondingDelegationUpdate struct {
		escrowID    signature.PublicKey
		delegatorID signature.PublicKey
		seq         uint64
		delegation  *staking.DebondingDelegation
	}
	var deups []debondingDelegationUpdate
	for keyEscrowID, delegators := range st.DebondingDelegations {
		var escrowID signature.PublicKey
		escrowID.FromMapKey(keyEscrowID)

		debondingShares := quantity.NewQuantity()
		for keyDelegatorID, delegations := range delegators {
			var delegatorID signature.PublicKey
			delegatorID.FromMapKey(keyDelegatorID)

			for idx, delegation := range delegations {
				if err := debondingShares.Add(&delegation.Shares); err != nil {
					app.logger.Error("InitChain: failed to add debonding delegation shares",
						"err", err,
					)
					return errors.Wrap(err, "staking/tendermint: failed to add debonding delegation shares")
				}

				deups = append(deups, debondingDelegationUpdate{escrowID, delegatorID, uint64(idx), delegation})
			}
		}

		acc := state.Account(escrowID)
		if acc.Escrow.Debonding.TotalShares.Cmp(debondingShares) != 0 {
			app.logger.Error("InitChain: debonding shares mismatch",
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

	app.initParameters(state, st)

	if err := app.initThresholds(state, st); err != nil {
		return err
	}

	if err := app.initCommonPool(st, &totalSupply); err != nil {
		return err
	}

	if err := app.initLedger(state, st, &totalSupply); err != nil {
		return err
	}

	app.initTotalSupply(state, st, &totalSupply)

	if err := app.initDelegations(state, st); err != nil {
		return err
	}

	if err := app.initDebondingDelegations(state, st); err != nil {
		return err
	}

	app.logger.Debug("InitChain: allocations complete",
		"debonding_interval", st.Parameters.DebondingInterval,
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

	thresholds, err := sq.state.Thresholds()
	if err != nil {
		return nil, err
	}

	debondingInterval, err := sq.state.DebondingInterval()
	if err != nil {
		return nil, err
	}

	rewardSchedule, err := sq.state.RewardSchedule()
	if err != nil {
		return nil, err
	}

	acceptableTransferPeers, err := sq.state.AcceptableTransferPeers()
	if err != nil {
		return nil, err
	}

	accounts, err := sq.state.Accounts()
	if err != nil {
		return nil, err
	}
	ledger := make(map[signature.MapKey]*staking.Account)
	for _, acctID := range accounts {
		acct := sq.state.Account(acctID)
		ledger[acctID.ToMapKey()] = acct
	}

	delegations, err := sq.state.Delegations()
	if err != nil {
		return nil, err
	}
	debondingDelegations, err := sq.state.DebondingDelegations()
	if err != nil {
		return nil, err
	}

	slashing, err := sq.state.Slashing()
	if err != nil {
		return nil, err
	}

	gen := staking.Genesis{
		Parameters: staking.ConsensusParameters{
			Thresholds:              thresholds,
			DebondingInterval:       epochtime.EpochTime(debondingInterval),
			RewardSchedule:          rewardSchedule,
			AcceptableTransferPeers: acceptableTransferPeers,
			Slashing:                slashing,
		},
		TotalSupply:          *totalSupply,
		CommonPool:           *commonPool,
		Ledger:               ledger,
		Delegations:          delegations,
		DebondingDelegations: debondingDelegations,
	}
	return &gen, nil
}
