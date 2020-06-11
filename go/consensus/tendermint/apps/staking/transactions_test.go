package staking

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestIsTransferPermitted(t *testing.T) {
	for _, tt := range []struct {
		msg       string
		params    *staking.ConsensusParameters
		fromAddr  staking.Address
		permitted bool
	}{
		{
			"no disablement",
			&staking.ConsensusParameters{},
			staking.Address{},
			true,
		},
		{
			"all disabled",
			&staking.ConsensusParameters{
				DisableTransfers: true,
			},
			staking.Address{},
			false,
		},
		{
			"not whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[staking.Address]bool{
					staking.Address{1}: true,
				},
			},
			staking.Address{},
			false,
		},
		{
			"whitelisted",
			&staking.ConsensusParameters{
				DisableTransfers: true,
				UndisableTransfersFrom: map[staking.Address]bool{
					staking.Address{}: true,
				},
			},
			staking.Address{},
			true,
		},
	} {
		require.Equal(t, tt.permitted, isTransferPermitted(tt.params, tt.fromAddr), tt.msg)
	}
}

func TestReservedAddresses(t *testing.T) {
	require := require.New(t)
	var err error

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer ctx.Close()

	stakeState := stakingState.NewMutableState(ctx.State())

	err = stakeState.SetConsensusParameters(ctx, &staking.ConsensusParameters{})
	require.NoError(err, "setting staking consensus parameters should not error")

	app := &stakingApplication{
		state: appState,
	}

	// Create a new test public key, set it as the tx signer and create a new reserved address from it.
	testPK := signature.NewPublicKey("badfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	ctx.SetTxSigner(testPK)
	_ = staking.NewReservedAddress(testPK)

	// Make sure all transaction types fail for the reserved address.
	err = app.transfer(ctx, stakeState, nil)
	require.EqualError(err, "staking: forbidden by policy", "transfer for reserved address should error")

	err = app.burn(ctx, stakeState, nil)
	require.EqualError(err, "staking: forbidden by policy", "burn for reserved address should error")

	var q quantity.Quantity
	_ = q.FromInt64(1_000)

	// NOTE: We need to specify escrow amount since that is checked before the check for reserved address.
	err = app.addEscrow(ctx, stakeState, &staking.Escrow{Tokens: *q.Clone()})
	require.EqualError(err, "staking: forbidden by policy", "adding escrow for reserved address should error")

	// NOTE: We need to specify reclaim escrow shares since that is checked before the check for reserved address.
	err = app.reclaimEscrow(ctx, stakeState, &staking.ReclaimEscrow{Shares: *q.Clone()})
	require.EqualError(err, "staking: forbidden by policy", "reclaim escrow for reserved address should error")

	err = app.amendCommissionSchedule(ctx, stakeState, nil)
	require.EqualError(err, "staking: forbidden by policy", "amending commission schedule for reserved address should error")
}
