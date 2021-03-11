package staking

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
	tmcrypto "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestOnEvidenceByzantineConsensus(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{
		// Use a non-zero current epoch so we test freeze overflow.
		CurrentEpoch: 42,
	})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	consensusSigner := memorySigner.NewTestSigner("consensus test signer")
	consensusID := consensusSigner.Public()
	validatorAddress := tmcrypto.PublicKeyToTendermint(&consensusID).Address()

	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	// Validator address is not known as there are no nodes.
	err := onEvidenceByzantineConsensus(ctx, staking.SlashConsensusEquivocation, validatorAddress, 1, now, 1)
	require.NoError(err, "should not fail when validator address is not known")

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
		ID:        nodeSigner.Public(),
		EntityID:  ent.ID,
		Consensus: node.ConsensusInfo{
			ID: consensusID,
		},
	}
	sigNode, err := node.MultiSignNode([]signature.Signer{nodeSigner}, registry.RegisterNodeSignatureContext, nod)
	require.NoError(err, "MultiSignNode")
	err = regState.SetNode(ctx, nil, nod, sigNode)
	require.NoError(err, "SetNode")

	// Should not fail if node status is not available.
	err = onEvidenceByzantineConsensus(ctx, staking.SlashConsensusEquivocation, validatorAddress, 1, now, 1)
	require.NoError(err, "should not fail when node status is not available")

	// Add node status.
	err = regState.SetNodeStatus(ctx, nod.ID, &registry.NodeStatus{})
	require.NoError(err, "SetNodeStatus")

	// Should fail if unable to get the slashing procedure.
	err = onEvidenceByzantineConsensus(ctx, staking.SlashConsensusEquivocation, validatorAddress, 1, now, 1)
	require.Error(err, "should fail when unable to get the slashing procedure")

	// Add slashing procedure.
	var slashAmount quantity.Quantity
	_ = slashAmount.FromUint64(100)
	err = stakeState.SetConsensusParameters(ctx, &staking.ConsensusParameters{
		Slashing: map[staking.SlashReason]staking.Slash{
			staking.SlashConsensusEquivocation: {
				Amount:         slashAmount,
				FreezeInterval: registry.FreezeForever,
			},
		},
	})
	require.NoError(err, "SetConsensusParameters")

	// Should not fail if the validator has no stake (which is in any case an
	// invariant violation as a validator needs to have some stake).
	err = onEvidenceByzantineConsensus(ctx, staking.SlashConsensusEquivocation, validatorAddress, 1, now, 1)
	require.NoError(err, "should not fail when validator has no stake")
	// Node should be frozen.
	status, err := regState.NodeStatus(ctx, nod.ID)
	require.NoError(err, "NodeStatus")
	require.True(status.IsFrozen(), "node should be frozen after slashing")
	require.EqualValues(registry.FreezeForever, status.FreezeEndTime, "node should be frozen forever")

	// Should not fail slashing a frozen node.
	err = onEvidenceByzantineConsensus(ctx, staking.SlashConsensusEquivocation, validatorAddress, 1, now, 1)
	require.NoError(err, "should not fail when validator is frozen")
	// Unfreeze the node.
	err = regState.SetNodeStatus(ctx, nod.ID, &registry.NodeStatus{FreezeEndTime: 0})
	require.NoError(err, "SetNodeStatus")

	// Computes entity's staking address.
	addr := staking.NewAddress(ent.ID)

	// Get the validator some stake.
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
	err = onEvidenceByzantineConsensus(ctx, staking.SlashConsensusEquivocation, validatorAddress, 1, now, 1)
	require.NoError(err, "slashing should succeed")

	// Entity stake should be slashed.
	acct, err := stakeState.Account(ctx, addr)
	require.NoError(err, "Account")
	_ = balance.Sub(&slashAmount)
	require.EqualValues(balance, acct.Escrow.Active.Balance, "entity stake should be slashed")

	// Node should be frozen.
	status, err = regState.NodeStatus(ctx, nod.ID)
	require.NoError(err, "NodeStatus")
	require.True(status.IsFrozen(), "node should be frozen after slashing")
	require.EqualValues(registry.FreezeForever, status.FreezeEndTime, "node should be frozen forever")

	// Should not fail in case the slashing penalty is not configured.
	err = onEvidenceByzantineConsensus(ctx, staking.SlashConsensusLightClientAttack, validatorAddress, 1, now, 1)
	require.NoError(err, "slashing should not fail")
}
