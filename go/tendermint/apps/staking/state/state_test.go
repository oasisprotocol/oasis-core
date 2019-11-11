package state

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/tendermint/iavl"
	dbm "github.com/tendermint/tm-db"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
)

func mustInitQuantity(t *testing.T, i int64) (q quantity.Quantity) {
	require.NoError(t, q.FromBigInt(big.NewInt(i)), "FromBigInt")
	return
}

func mustInitQuantityP(t *testing.T, i int64) *quantity.Quantity {
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
	escrowAccountOnly := []signature.PublicKey{escrowID}
	escrowAccount := &staking.Account{}

	del := &staking.Delegation{}
	require.NoError(t, escrowAccount.Escrow.Active.Deposit(&del.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100)), "active escrow deposit")

	deb := &staking.DebondingDelegation{}
	deb.DebondEndTime = 21
	require.NoError(t, escrowAccount.Escrow.Debonding.Deposit(&deb.Shares, &delegatorAccount.General.Balance, mustInitQuantityP(t, 100)), "debonding escrow deposit")

	db := dbm.NewMemDB()
	tree := iavl.NewMutableTree(db, 128)
	s := NewMutableState(tree)

	s.SetConsensusParameters(&staking.ConsensusParameters{
		DebondingInterval: 21,
		RewardSchedule: []staking.RewardStep{
			{
				Until: 30,
				Scale: mustInitQuantity(t, 1000),
			},
			{
				Until: 40,
				Scale: mustInitQuantity(t, 500),
			},
		},
	})
	s.SetCommonPool(mustInitQuantityP(t, 10000))

	s.SetAccount(delegatorID, delegatorAccount)
	s.SetAccount(escrowID, escrowAccount)
	s.SetDelegation(delegatorID, escrowID, del)
	s.SetDebondingDelegation(delegatorID, escrowID, 1, deb)

	// Epoch 10 is during the first step.
	require.NoError(t, s.AddRewards(10, mustInitQuantityP(t, 100), escrowAccountOnly), "add rewards epoch 10")

	// 100% gain.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(t, mustInitQuantity(t, 100), delegatorAccount.General.Balance, "reward first step - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 200), escrowAccount.Escrow.Active.Balance, "reward first step - escrow active escrow")
	require.Equal(t, mustInitQuantity(t, 100), escrowAccount.Escrow.Debonding.Balance, "reward first step - escrow debonding escrow")
	commonPool, err := s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 9900), commonPool, "reward first step - common pool")

	// Epoch 30 is in the second step.
	require.NoError(t, s.AddRewards(30, mustInitQuantityP(t, 100), escrowAccountOnly), "add rewards epoch 30")

	// 50% gain.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward boundary epoch - escrow active escrow")
	commonPool, err = s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 9800), commonPool, "reward first step - common pool")

	// Epoch 99 is after the end of the schedule
	require.NoError(t, s.AddRewards(99, mustInitQuantityP(t, 100), escrowAccountOnly), "add rewards epoch 99")

	// No change.
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 300), escrowAccount.Escrow.Active.Balance, "reward late epoch - escrow active escrow")

	slashedNonzero, err := s.SlashEscrow(abci.NewContext(abci.ContextDeliverTx, time.Now(), nil), escrowID, mustInitQuantityP(t, 10_000))
	require.NoError(t, err, "slash escrow")
	require.True(t, slashedNonzero, "slashed nonzero")

	// 10% loss.
	delegatorAccount = s.Account(delegatorID)
	require.Equal(t, mustInitQuantity(t, 100), delegatorAccount.General.Balance, "slash - delegator general")
	escrowAccount = s.Account(escrowID)
	require.Equal(t, mustInitQuantity(t, 270), escrowAccount.Escrow.Active.Balance, "slash - escrow active escrow")
	require.Equal(t, mustInitQuantity(t, 90), escrowAccount.Escrow.Debonding.Balance, "slash - escrow debonding escrow")
	commonPool, err = s.CommonPool()
	require.NoError(t, err, "load common pool")
	require.Equal(t, mustInitQuantityP(t, 9840), commonPool, "slash - common pool")
}
