package roothash

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestOnEvidenceRuntimeEquivocation(t *testing.T) {
	require := require.New(t)

	amount := quantity.NewFromUint64(100)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	runtime := registry.Runtime{}
	testNodeSigner := memorySigner.NewTestSigner("runtime test signer")

	// Signer is not known as there are no nodes.
	err := onEvidenceRuntimeEquivocation(
		ctx,
		testNodeSigner.Public(),
		runtime.ID,
		amount,
	)
	require.Error(err, "should fail when evidence signer address is not known")

	// Add entity.
	ent, entitySigner, _ := entity.TestEntity()
	sigEntity, err := entity.SignEntity(entitySigner, registry.RegisterEntitySignatureContext, ent)
	require.NoError(err, "SignEntity")
	err = regState.SetEntity(ctx, ent, sigEntity)
	require.NoError(err, "SetEntity")
	// Add node.
	nodeSigner := memorySigner.NewTestSigner("node test signer")
	nod := &node.Node{
		Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:        testNodeSigner.Public(),
		EntityID:  ent.ID,
		Consensus: node.ConsensusInfo{},
	}
	sigNode, err := node.MultiSignNode([]signature.Signer{nodeSigner}, registry.RegisterNodeSignatureContext, nod)
	require.NoError(err, "MultiSignNode")
	err = regState.SetNode(ctx, nil, nod, sigNode)
	require.NoError(err, "SetNode")

	// Should fail if the node has no stake.
	err = onEvidenceRuntimeEquivocation(
		ctx,
		testNodeSigner.Public(),
		runtime.ID,
		amount,
	)
	require.Error(err, "should fail when node has no stake")

	// Give entity some stake.
	addr := staking.NewAddress(ent.ID)
	var balance quantity.Quantity
	_ = balance.FromUint64(200)
	var totalShares quantity.Quantity
	_ = totalShares.FromUint64(200)
	err = stakeState.SetAccount(ctx, addr, &staking.Account{
		Escrow: staking.EscrowAccount{
			Active: staking.SharePool{
				Balance:     balance,
				TotalShares: totalShares,
			},
		},
	})
	require.NoError(err, "SetAccount")

	// Should slash.
	err = onEvidenceRuntimeEquivocation(
		ctx,
		testNodeSigner.Public(),
		runtime.ID,
		amount,
	)
	require.NoError(err, "slashing should succeed")

	// Entity stake should be slashed.
	acct, err := stakeState.Account(ctx, addr)
	require.NoError(err, "Account")
	require.NoError(balance.Sub(amount))
	require.EqualValues(balance, acct.Escrow.Active.Balance, "entity stake should be slashed")

	// Runtime account should get the slashed amount.
	rtAcc, err := stakeState.Account(ctx, staking.NewRuntimeAddress(runtime.ID))
	require.NoError(err, "runtime Addr")
	require.EqualValues(amount, &rtAcc.General.Balance, "runtime account should get slashed amount")
}
