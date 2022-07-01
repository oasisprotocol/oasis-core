package tests

import (
	"math"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
)

// NumAccounts corresponds to the number of staking accounts used in the
// staking genesis state as returned by GenesisState.
const NumAccounts = 7

// Accounts stores an AccountList with staking accounts used in the
// staking genesis state as returned by GenesisState.
var Accounts = newAccountList()

// newAccountList generates a new AccountList for the required number of
// staking accounts.
func newAccountList() AccountList {
	accts := make([]account, NumAccounts)
	for i := 0; i < NumAccounts; i++ {
		accts[i] = newAccount()
	}
	return accts
}

// GenesisState returns a staking genesis state that can be used in tests.
func GenesisState() api.Genesis {
	state := api.Genesis{
		Parameters: api.ConsensusParameters{
			DebondingInterval: 1,
			Thresholds: map[api.ThresholdKind]quantity.Quantity{
				api.KindEntity:            *quantity.NewFromUint64(1),
				api.KindNodeValidator:     *quantity.NewFromUint64(2),
				api.KindNodeCompute:       *quantity.NewFromUint64(3),
				api.KindNodeKeyManager:    *quantity.NewFromUint64(5),
				api.KindRuntimeCompute:    *quantity.NewFromUint64(6),
				api.KindRuntimeKeyManager: *quantity.NewFromUint64(7),
			},
			Slashing: map[api.SlashReason]api.Slash{
				api.SlashConsensusEquivocation: {
					Amount:         *quantity.NewFromUint64(math.MaxInt64), // Slash everything.
					FreezeInterval: 1,
				},
			},
			MinDelegationAmount: *quantity.NewFromUint64(10),
			MinTransferAmount:   *quantity.NewFromUint64(10),
			// Zero MinTransactBalance is normal.
			MaxAllowances:           32,
			FeeSplitWeightVote:      *quantity.NewFromUint64(1),
			RewardFactorEpochSigned: *quantity.NewFromUint64(1),
			// Zero RewardFactorBlockProposed is normal.
		},
		TokenSymbol: "TEST",
		TotalSupply: *quantity.NewFromUint64(math.MaxInt64),
		Ledger: map[api.Address]*api.Account{
			Accounts.GetAddress(1): {
				General: api.GeneralAccount{
					Balance: *quantity.NewFromUint64(math.MaxInt32),
				},
				Escrow: api.EscrowAccount{
					Active: api.SharePool{
						Balance: *quantity.NewFromUint64(100),
						// Amount of shares will be automatically computed.
					},
				},
			},
			Accounts.GetAddress(3): {
				General: api.GeneralAccount{
					Balance: *quantity.NewFromUint64(math.MaxInt32),
				},
				Escrow: api.EscrowAccount{
					Active: api.SharePool{
						Balance: *quantity.NewFromUint64(5000),
						// Amount of shares will be automatically computed.
					},
					Debonding: api.SharePool{
						Balance: *quantity.NewFromUint64(3000),
						// Amount of shares will be automatically computed.
					},
				},
			},
			Accounts.GetAddress(4): {
				General: api.GeneralAccount{
					Balance: *quantity.NewFromUint64(math.MaxInt32),
				},
				Escrow: api.EscrowAccount{
					Active: api.SharePool{
						Balance: *quantity.NewFromUint64(150_000),
						// Amount of shares will be automatically computed.
					},
					Debonding: api.SharePool{
						Balance: *quantity.NewFromUint64(300_000),
						// Amount of shares will be automatically computed.
					},
				},
			},
			Accounts.GetAddress(7): {
				General: api.GeneralAccount{
					Balance: *quantity.NewFromUint64(math.MaxInt16),
				},
				Escrow: api.EscrowAccount{
					Active: api.SharePool{
						Balance: *quantity.NewFromUint64(42_000),
						// Amount of shares will be automatically computed.
					},
					Debonding: api.SharePool{
						Balance: *quantity.NewFromUint64(9000),
						// Amount of shares will be automatically computed.
					},
				},
			},
		},
		Delegations: map[api.Address]map[api.Address]*api.Delegation{
			Accounts.GetAddress(1): {
				Accounts.GetAddress(1): {
					Shares: *quantity.NewFromUint64(1000),
				},
			},
			Accounts.GetAddress(3): {
				Accounts.GetAddress(2): {
					Shares: *quantity.NewFromUint64(1000),
				},
				Accounts.GetAddress(5): {
					Shares: *quantity.NewFromUint64(5000),
				},
			},
			Accounts.GetAddress(4): {
				Accounts.GetAddress(2): {
					Shares: *quantity.NewFromUint64(2000),
				},
				Accounts.GetAddress(3): {
					Shares: *quantity.NewFromUint64(3000),
				},
				Accounts.GetAddress(5): {
					Shares: *quantity.NewFromUint64(5000),
				},
				Accounts.GetAddress(6): {
					Shares: *quantity.NewFromUint64(10_000),
				},
			},
			Accounts.GetAddress(7): {
				Accounts.GetAddress(1): {
					Shares: *quantity.NewFromUint64(4000),
				},
				Accounts.GetAddress(5): {
					Shares: *quantity.NewFromUint64(20_000),
				},
				Accounts.GetAddress(7): {
					Shares: *quantity.NewFromUint64(7000),
				},
			},
		},
		DebondingDelegations: map[api.Address]map[api.Address][]*api.DebondingDelegation{
			Accounts.GetAddress(3): {
				Accounts.GetAddress(2): {
					{
						Shares:        *quantity.NewFromUint64(1000),
						DebondEndTime: beacon.EpochTime(100),
					},
					{
						Shares:        *quantity.NewFromUint64(500),
						DebondEndTime: beacon.EpochTime(150),
					},
				},
				Accounts.GetAddress(5): {
					{
						Shares:        *quantity.NewFromUint64(3000),
						DebondEndTime: beacon.EpochTime(100),
					},
				},
			},
			Accounts.GetAddress(4): {
				Accounts.GetAddress(3): {
					{
						Shares:        *quantity.NewFromUint64(1000),
						DebondEndTime: beacon.EpochTime(100),
					},
				},
				Accounts.GetAddress(4): {
					{
						Shares:        *quantity.NewFromUint64(300),
						DebondEndTime: beacon.EpochTime(100),
					},
					{
						Shares:        *quantity.NewFromUint64(2000),
						DebondEndTime: beacon.EpochTime(150),
					},
				},
				Accounts.GetAddress(6): {
					{
						Shares:        *quantity.NewFromUint64(3000),
						DebondEndTime: beacon.EpochTime(100),
					},
					{
						Shares:        *quantity.NewFromUint64(1000),
						DebondEndTime: beacon.EpochTime(150),
					},
					{
						Shares:        *quantity.NewFromUint64(5000),
						DebondEndTime: beacon.EpochTime(200),
					},
					{
						Shares:        *quantity.NewFromUint64(4000),
						DebondEndTime: beacon.EpochTime(250),
					},
				},
				Accounts.GetAddress(7): {
					{
						Shares:        *quantity.NewFromUint64(2000),
						DebondEndTime: beacon.EpochTime(175),
					},
					{
						Shares:        *quantity.NewFromUint64(9000),
						DebondEndTime: beacon.EpochTime(220),
					},
					{
						Shares:        *quantity.NewFromUint64(4000),
						DebondEndTime: beacon.EpochTime(270),
					},
				},
			},
			Accounts.GetAddress(7): {
				Accounts.GetAddress(3): {
					{
						Shares:        *quantity.NewFromUint64(3000),
						DebondEndTime: beacon.EpochTime(100),
					},
				},
				Accounts.GetAddress(6): {
					{
						Shares:        *quantity.NewFromUint64(1000),
						DebondEndTime: beacon.EpochTime(100),
					},
					{
						Shares:        *quantity.NewFromUint64(500),
						DebondEndTime: beacon.EpochTime(150),
					},
				},
			},
		},
	}

	// Adjust common pool for the remaining balance.
	remainingBalance := state.TotalSupply.Clone()
	for _, acc := range state.Ledger {
		if err := remainingBalance.Sub(&acc.General.Balance); err != nil {
			panic(err)
		}
		if err := remainingBalance.Sub(&acc.Escrow.Active.Balance); err != nil {
			panic(err)
		}
		if err := remainingBalance.Sub(&acc.Escrow.Debonding.Balance); err != nil {
			panic(err)
		}
	}
	state.CommonPool = *remainingBalance

	// Compute total shares for all accounts.
	for addr, dels := range state.Delegations {
		totalShares := quantity.NewQuantity()
		for _, del := range dels {
			if err := totalShares.Add(&del.Shares); err != nil {
				panic(err)
			}
		}
		state.Ledger[addr].Escrow.Active.TotalShares = *totalShares
	}
	for addr, debDelLists := range state.DebondingDelegations {
		totalShares := quantity.NewQuantity()
		for _, debDelList := range debDelLists {
			for _, debDel := range debDelList {
				if err := totalShares.Add(&debDel.Shares); err != nil {
					panic(err)
				}
			}
		}
		state.Ledger[addr].Escrow.Debonding.TotalShares = *totalShares
	}

	return state
}
