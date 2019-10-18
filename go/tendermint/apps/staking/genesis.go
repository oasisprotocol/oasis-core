package staking

import (
	"bytes"
	"sort"

	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

// InitChain initializes the chain from genesis.
func (app *stakingApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	type thresholdUpdate struct {
		k staking.ThresholdKind
		v staking.Quantity
	}

	type ledgerUpdate struct {
		id      signature.PublicKey
		account *staking.Account
	}

	st := &doc.Staking
	if app.debugGenesisState != nil {
		if len(st.Ledger) > 0 {
			app.logger.Error("InitChain: debug genesis state and actual genesis state provided")
			return errors.New("staking/tendermint: multiple genesis states specified")
		}
		st = app.debugGenesisState
	}

	var (
		state       = NewMutableState(app.state.DeliverTxTree())
		totalSupply staking.Quantity
	)

	state.setDebondingInterval(uint64(st.DebondingInterval))
	state.setAcceptableTransferPeers(st.AcceptableTransferPeers)

	// Thresholds.
	if st.Thresholds != nil {
		var ups []thresholdUpdate
		for k, v := range st.Thresholds {
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
			state.setThreshold(u.k, &u.v)
		}
	}

	if !st.CommonPool.IsValid() {
		return errors.New("staking/tendermint: invalid genesis state CommonPool")
	}
	if err := totalSupply.Add(&st.CommonPool); err != nil {
		app.logger.Error("InitChain: failed to add common pool",
			"err", err,
		)
		return errors.Wrap(err, "staking/tendermint: failed to add common pool")
	}

	// Ledger.
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
		if !v.Escrow.Balance.IsValid() {
			app.logger.Error("InitChain: invalid genesis escrow balance",
				"id", id,
				"escrow_balance", v.Escrow.Balance,
			)
			return errors.New("staking/tendermint: invalid genesis escrow balance")
		}

		ups = append(ups, ledgerUpdate{id, v})
		if err := totalSupply.Add(&v.General.Balance); err != nil {
			app.logger.Error("InitChain: failed to add general balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add general balance")
		}
		if err := totalSupply.Add(&v.Escrow.Balance); err != nil {
			app.logger.Error("InitChain: failed to add escrow balance",
				"err", err,
			)
			return errors.Wrap(err, "staking/tendermint: failed to add escrow balance")
		}
	}

	// Make sure that we apply ledger updates in a canonical order.
	sort.SliceStable(ups, func(i, j int) bool { return bytes.Compare(ups[i].id[:], ups[j].id[:]) < 0 })
	for _, u := range ups {
		state.setAccount(u.id, u.account)
	}

	if totalSupply.Cmp(&st.TotalSupply) != 0 {
		app.logger.Error("InitChain: total supply mismatch",
			"expected", st.TotalSupply,
			"actual", totalSupply,
		)
	}

	// Delegations.
	type delegationUpdate struct {
		escrowID    signature.PublicKey
		delegatorID signature.PublicKey
		delegation  *staking.Delegation
	}

	var dups []delegationUpdate
	for keyEscrowID, delegations := range st.Delegations {
		var escrowID signature.PublicKey
		escrowID.FromMapKey(keyEscrowID)

		delegationShares := staking.NewQuantity()
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

		acc := state.account(escrowID)
		if acc.Escrow.TotalShares.Cmp(delegationShares) != 0 {
			app.logger.Error("InitChain: total shares mismatch",
				"escrow_id", escrowID,
				"expected", acc.Escrow.TotalShares,
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
		state.setDelegation(u.delegatorID, u.escrowID, u.delegation)
	}

	// Debonding delegations.
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

		debondingShares := staking.NewQuantity()
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

		acc := state.account(escrowID)
		if acc.Escrow.DebondingShares.Cmp(debondingShares) != 0 {
			app.logger.Error("InitChain: debonding shares mismatch",
				"escrow_id", escrowID,
				"expected", acc.Escrow.DebondingShares,
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
		state.setDebondingDelegation(u.delegatorID, u.escrowID, u.seq, u.delegation)
	}

	state.setCommonPool(&st.CommonPool)
	state.setTotalSupply(&totalSupply)

	app.logger.Debug("InitChain: allocations complete",
		"debonding_interval", st.DebondingInterval,
		"common_pool", st.CommonPool,
		"total_supply", totalSupply,
	)

	return nil
}

// queryGenesis exports current state in genesis format.
func (app *stakingApplication) queryGenesis(s, r interface{}) ([]byte, error) {
	state := s.(*immutableState)

	totalSupply, err := state.totalSupply()
	if err != nil {
		return nil, err
	}

	commonPool, err := state.CommonPool()
	if err != nil {
		return nil, err
	}

	thresholds, err := state.Thresholds()
	if err != nil {
		return nil, err
	}

	debondingInterval, err := state.debondingInterval()
	if err != nil {
		return nil, err
	}

	accounts, err := state.accounts()
	if err != nil {
		return nil, err
	}
	ledger := make(map[signature.MapKey]*staking.Account)
	for _, acctID := range accounts {
		acct := state.account(acctID)
		ledger[acctID.ToMapKey()] = acct
	}

	delegations, err := state.delegations()
	if err != nil {
		return nil, err
	}
	debondingDelegations, err := state.debondingDelegations()
	if err != nil {
		return nil, err
	}

	gen := staking.Genesis{
		TotalSupply:          *totalSupply,
		CommonPool:           *commonPool,
		Thresholds:           thresholds,
		DebondingInterval:    epochtime.EpochTime(debondingInterval),
		Ledger:               ledger,
		Delegations:          delegations,
		DebondingDelegations: debondingDelegations,
	}
	return cbor.Marshal(gen), nil
}
