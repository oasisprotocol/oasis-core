package state

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/iavl"
	dbm "github.com/tendermint/tm-db"

	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

func mustInitQuantity(t *testing.T, i int64) (q staking.Quantity) {
	require.NoError(t, q.FromBigInt(big.NewInt(i)), "FromBigInt")
	return
}

func mustInitQuantityP(t *testing.T, i int64) *staking.Quantity {
	q := mustInitQuantity(t, i)
	return &q
}

func TestRewardAndSlash(t *testing.T) {
	delegatorSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "generating delegator signer")
	delegatorID := delegatorSigner.Public()
	delegatorAccount := &staking.Account{}
	delegatorAccount.General.Nonce = 10
	require.NoError(t, delegatorAccount.General.Balance.FromBigInt(big.NewInt(300)), "initialize delegator account general balance")

	escrowSigner, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "generating escrow signer")
	escrowID := escrowSigner.Public()
	escrowAccount := &staking.Account{}

	del := &staking.Delegation{}
	require.NoError(t, escrowAccount.Escrow.Active.Deposit(&del.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100)), "active escrow deposit")

	deb := &staking.DebondingDelegation{}
	deb.DebondEndTime = 21
	require.NoError(t, escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100)), "debonding escrow deposit")

	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)
	s := NewMutableState(tree)

	s.SetDebondingInterval(21)
	s.SetRewardSchedule([]staking.RewardStep{
		// 0 (but not triggered), 10, 20
		{
			Until:       30,
			Interval:    10,
			Numerator:   mustInitQuantity(t, 1),
			Denominator: mustInitQuantity(t, 1),
		},
		// 30, 38
		{
			Until:       40,
			Interval:    8,
			Numerator:   mustInitQuantity(t, 1),
			Denominator: mustInitQuantity(t, 2),
		},
	})

	s.SetAccount(delegatorID, delegatorAccount)
	s.SetAccount(escrowID, escrowAccount)
	s.SetDelegation(delegatorID, escrowID, del)
	s.SetDebondingDelegation(delegatorID, escrowID, 1, deb)

	// There is no processing done on epoch 0.
	// Epoch 1 is before a whole interval elapses.
	require.NoError(t, s.AddRewards(1), "add rewards epoch 1")

	// No change.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(t, mustInitQuantity(t, 100), delegatorAccount.General.Balance, "reward non-interval - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 100), escrowAccount.Escrow.Active.Balance, "reward non-interval - escrow active escrow")
	require.Equal(t, mustInitQuantity(t, 100), escrowAccount.Escrow.Debonding.Balance, "reward non-interval - escrow debonding escrow")

	// Epoch 10 is the first interval of the first step.
	require.NoError(t, s.AddRewards(10), "add rewards epoch 10")

	// 1/1 gain.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(t, mustInitQuantity(t, 100), delegatorAccount.General.Balance, "reward first step - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 200), escrowAccount.Escrow.Active.Balance, "reward first step - escrow active escrow")
	require.Equal(t, mustInitQuantity(t, 100), escrowAccount.Escrow.Debonding.Balance, "reward first step - escrow debonding escrow")

	// At epoch 30, the first step is over, and the second step is in effect.
	require.NoError(t, s.AddRewards(30), "add rewards epoch 30")

	// 1/2 gain.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward boundary epoch - escrow active escrow")

	// Epoch 38 is epoch 8 of the second step, which is the end of the interval.
	require.NoError(t, s.AddRewards(38), "add rewards epoch 38")

	// 1/2 gain.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 450), escrowAccount.Escrow.Active.Balance, "reward second step - escrow active escrow")

	// Epoch 99 is after the end of the schedule
	require.NoError(t, s.AddRewards(99), "add rewards epoch 99")

	// No change.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 450), escrowAccount.Escrow.Active.Balance, "reward late epoch - escrow active escrow")

	slashedNonzero, err := s.SlashEscrow(abci.NewContext(abci.ContextDeliverTx, time.Now(), nil), escrowID, mustInitQuantityP(t, 2), mustInitQuantityP(t, 3))
	require.NoError(t, err, "slash escrow")
	require.True(t, slashedNonzero, "slashed nonzero")

	// 2/3 keep = 1/3 loss, kept amount rounded down, slashed amount rounded up.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(t, mustInitQuantity(t, 100), delegatorAccount.General.Balance, "slash - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "slash - escrow active escrow")
	require.Equal(t, mustInitQuantity(t, 66), escrowAccount.Escrow.Debonding.Balance, "slash - escrow debonding escrow")
	commonPool, err := s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 184), commonPool, "slash - common pool")
}
