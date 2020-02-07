package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func TestStakeAccumulatorCache(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abci.NewMockApplicationState(abci.MockApplicationStateConfig{})
	ctx := appState.NewContext(abci.ContextBeginBlock, now)
	defer ctx.Close()

	_, err := NewStakeAccumulatorCache(ctx)
	require.Error(err, "NewStakeAccumulatorCache should fail without consensus parameters")

	stakeState := NewMutableState(ctx.State())
	var q quantity.Quantity
	_ = q.FromInt64(1_000)
	stakeState.SetConsensusParameters(&staking.ConsensusParameters{
		Thresholds: map[staking.ThresholdKind]quantity.Quantity{
			staking.KindEntity: *q.Clone(),
		},
	})

	acc, err := NewStakeAccumulatorCache(ctx)
	require.NoError(err, "NewStakeAccumulatorCache")

	// NOTE: Most of the code is just calling into the stake accumulator related methods on the
	//       escrow account instance which is tested separately. Here we just make sure that state
	//       changes are propagated correctly.

	ent, _, _ := entity.TestEntity()
	var acct staking.Account
	acct.Escrow.Active.Balance = *q.Clone()
	stakeState.SetAccount(ent.ID, &acct)

	err = acc.AddStakeClaim(ent.ID, staking.StakeClaim("claim"), []staking.ThresholdKind{staking.KindEntity})
	require.NoError(err, "AddStakeClaim")

	err = acc.CheckStakeClaims(ent.ID)
	require.NoError(err, "CheckStakeClaims")

	balance := acc.GetEscrowBalance(ent.ID)
	require.Equal(acct.Escrow.Active.Balance, balance, "GetEscrowBalance should return the correct balance")

	// Check that nothing has been committed yet.
	acct2 := stakeState.Account(ent.ID)
	require.Len(acct2.Escrow.StakeAccumulator.Claims, 0, "claims should not be updated yet")

	// Now commit and re-check.
	acc.Commit()
	acct2 = stakeState.Account(ent.ID)
	require.Len(acct2.Escrow.StakeAccumulator.Claims, 1, "claims should be correct")

	err = acc.RemoveStakeClaim(ent.ID, staking.StakeClaim("claim"))
	require.NoError(err, "RemoveStakeClaim")

	// Check that nothing has been committed.
	acct2 = stakeState.Account(ent.ID)
	require.Len(acct2.Escrow.StakeAccumulator.Claims, 1, "claims should not be updated")

	acc.Discard()
	acct2 = stakeState.Account(ent.ID)
	require.Len(acct2.Escrow.StakeAccumulator.Claims, 1, "claims should not be updated")

	// Test convenience functions.
	err = AddStakeClaim(ctx, ent.ID, staking.StakeClaim("claim"), []staking.ThresholdKind{staking.KindEntity})
	require.NoError(err, "AddStakeClaim")
	err = RemoveStakeClaim(ctx, ent.ID, staking.StakeClaim("claim"))
	require.NoError(err, "RemoveStakeClaim")
	err = CheckStakeClaims(ctx, ent.ID)
	require.NoError(err, "CheckStakeClaims")
}
