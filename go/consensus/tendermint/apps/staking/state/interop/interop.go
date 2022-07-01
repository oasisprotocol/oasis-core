package interop

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
)

var addresses []staking.Address

// InitializeTestStakingState must be kept in sync with tests in runtimes/consensus/state/staking.rs.
func InitializeTestStakingState(ctx context.Context, mkvs mkvs.Tree) error {
	state := stakingState.NewMutableState(mkvs)

	// Populate accounts.
	for _, acc := range []struct {
		address staking.Address
		account *staking.Account
	}{
		{
			addresses[0],
			&staking.Account{
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(23),
					Nonce:   13,
				},
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(100),
						TotalShares: *quantity.NewFromUint64(10),
					},
					Debonding: staking.SharePool{
						Balance:     *quantity.NewFromUint64(5),
						TotalShares: *quantity.NewFromUint64(5),
					},
				},
			},
		},
		{
			addresses[1],
			&staking.Account{
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(23),
					Nonce:   1,
				},
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(500),
						TotalShares: *quantity.NewFromUint64(5),
					},
				},
			},
		},
		{
			addresses[2],
			&staking.Account{
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(113),
					Nonce:   17,
				},
				Escrow: staking.EscrowAccount{
					Active: staking.SharePool{
						Balance:     *quantity.NewFromUint64(400),
						TotalShares: *quantity.NewFromUint64(35),
					},
				},
			},
		},
	} {
		if err := state.SetAccount(ctx, acc.address, acc.account); err != nil {
			return fmt.Errorf("setting account: %w", err)
		}
	}

	// Initialize delegations.
	for _, del := range []struct {
		from staking.Address
		to   staking.Address
		d    *staking.Delegation
	}{
		{
			from: addresses[0],
			to:   addresses[0],
			d: &staking.Delegation{
				Shares: *quantity.NewFromUint64(5),
			},
		},
		{
			from: addresses[0],
			to:   addresses[2],
			d: &staking.Delegation{
				Shares: *quantity.NewFromUint64(20),
			},
		},
		{
			from: addresses[1],
			to:   addresses[0],
			d: &staking.Delegation{
				Shares: *quantity.NewFromUint64(5),
			},
		},
		{
			from: addresses[1],
			to:   addresses[2],
			d: &staking.Delegation{
				Shares: *quantity.NewFromUint64(6),
			},
		},
		{
			from: addresses[2],
			to:   addresses[1],
			d: &staking.Delegation{
				Shares: *quantity.NewFromUint64(5),
			},
		},
		{
			from: addresses[2],
			to:   addresses[2],
			d: &staking.Delegation{
				Shares: *quantity.NewFromUint64(10),
			},
		},
	} {
		if err := state.SetDelegation(ctx, del.from, del.to, del.d); err != nil {
			return err
		}
	}

	// Initialize debonding delegations.
	for _, deb := range []struct {
		from staking.Address
		to   staking.Address
		d    *staking.DebondingDelegation
	}{
		{
			from: addresses[0],
			to:   addresses[0],
			d: &staking.DebondingDelegation{
				Shares:        *quantity.NewFromUint64(1),
				DebondEndTime: 33,
			},
		},
		{
			from: addresses[1],
			to:   addresses[0],
			d: &staking.DebondingDelegation{
				Shares:        *quantity.NewFromUint64(1),
				DebondEndTime: 15,
			},
		},
		{
			from: addresses[1],
			to:   addresses[0],
			d: &staking.DebondingDelegation{
				Shares:        *quantity.NewFromUint64(1),
				DebondEndTime: 21,
			},
		},
		{
			from: addresses[2],
			to:   addresses[0],
			d: &staking.DebondingDelegation{
				Shares:        *quantity.NewFromUint64(2),
				DebondEndTime: 100,
			},
		},
	} {
		if err := state.SetDebondingDelegation(ctx, deb.from, deb.to, deb.d.DebondEndTime, deb.d); err != nil {
			return err
		}
	}

	// Initialize balances.
	if err := state.SetTotalSupply(ctx, quantity.NewFromUint64(10000)); err != nil {
		return err
	}
	if err := state.SetCommonPool(ctx, quantity.NewFromUint64(1000)); err != nil {
		return err
	}
	if err := state.SetLastBlockFees(ctx, quantity.NewFromUint64(33)); err != nil {
		return err
	}
	if err := state.SetGovernanceDeposits(ctx, quantity.NewFromUint64(12)); err != nil {
		return err
	}

	return nil
}

func init() {
	pk := signature.NewPublicKey("7e57baaad01fffffffffffffffffffffffffffffffffffffffffffffffffffff")
	pk2 := signature.NewPublicKey("7e57baaad02fffffffffffffffffffffffffffffffffffffffffffffffffffff")
	pk3 := signature.NewPublicKey("7e57baaad03fffffffffffffffffffffffffffffffffffffffffffffffffffff")
	addresses = append(addresses,
		staking.NewAddress(pk),
		staking.NewAddress(pk2),
		staking.NewAddress(pk3),
	)
}
