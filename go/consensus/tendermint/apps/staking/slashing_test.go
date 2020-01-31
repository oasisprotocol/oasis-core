package staking

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	stakingState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/staking/state"
	tmcrypto "github.com/oasislabs/oasis-core/go/consensus/tendermint/crypto"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

func TestOnEvidenceDoubleSign(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abci.NewMockApplicationState(abci.MockApplicationStateConfig{
		// Use a non-zero current epoch so we test freeze overflow.
		CurrentEpoch: 42,
	})
	ctx := appState.NewContext(abci.ContextBeginBlock, now)
	defer ctx.Close()

	consensusSigner := memorySigner.NewTestSigner("consensus test signer")
	consensusID := consensusSigner.Public()
	validatorAddress := tmcrypto.PublicKeyToTendermint(&consensusID).Address()

	regState := registryState.NewMutableState(ctx.State())
	stakeState := stakingState.NewMutableState(ctx.State())

	// Validator address is not known as there are no nodes.
	err := onEvidenceDoubleSign(ctx, validatorAddress, 1, now, 1)
	require.NoError(err, "should not fail when validator address is not known")

	// Add entity.
	ent, entitySigner, _ := entity.TestEntity()
	sigEntity, err := entity.SignEntity(entitySigner, registry.RegisterEntitySignatureContext, ent)
	require.NoError(err, "SignEntity")
	regState.SetEntity(ent, sigEntity)
	// Add node.
	nodeSigner := memorySigner.NewTestSigner("node test signer")
	nod := &node.Node{
		ID:       nodeSigner.Public(),
		EntityID: ent.ID,
		Consensus: node.ConsensusInfo{
			ID: consensusID,
		},
	}
	sigNode, err := node.MultiSignNode([]signature.Signer{nodeSigner}, registry.RegisterNodeSignatureContext, nod)
	require.NoError(err, "MultiSignNode")
	err = regState.SetNode(nod, sigNode)
	require.NoError(err, "SetNode")

	// Should not fail if node status is not available.
	err = onEvidenceDoubleSign(ctx, validatorAddress, 1, now, 1)
	require.NoError(err, "should not fail when node status is not available")

	// Add node status.
	err = regState.SetNodeStatus(nod.ID, &registry.NodeStatus{})
	require.NoError(err, "SetNodeStatus")

	// Should fail if unable to get the slashing procedure.
	err = onEvidenceDoubleSign(ctx, validatorAddress, 1, now, 1)
	require.Error(err, "should fail when unable to get the slashing procedure")

	// Add slashing procedure.
	var slashAmount quantity.Quantity
	_ = slashAmount.FromUint64(100)
	stakeState.SetConsensusParameters(&staking.ConsensusParameters{
		Slashing: map[staking.SlashReason]staking.Slash{
			staking.SlashDoubleSigning: staking.Slash{
				Amount:         slashAmount,
				FreezeInterval: registry.FreezeForever,
			},
		},
	})

	// Should fail as the validator has no stake (which is an invariant violation as a validator
	// needs to have some stake).
	err = onEvidenceDoubleSign(ctx, validatorAddress, 1, now, 1)
	require.Error(err, "should fail when validator has no stake")

	// Get the validator some stake.
	var balance quantity.Quantity
	_ = balance.FromUint64(200)
	var totalShares quantity.Quantity
	_ = totalShares.FromUint64(200)
	stakeState.SetAccount(ent.ID, &staking.Account{
		Escrow: staking.EscrowAccount{
			Active: staking.SharePool{
				Balance:     balance,
				TotalShares: totalShares,
			},
		},
	})

	// Should slash.
	err = onEvidenceDoubleSign(ctx, validatorAddress, 1, now, 1)
	require.NoError(err, "slashing should succeed")

	// Entity stake should be slashed.
	acct := stakeState.Account(ent.ID)
	_ = balance.Sub(&slashAmount)
	require.EqualValues(balance, acct.Escrow.Active.Balance, "entity stake should be slashed")

	// Node should be frozen.
	status, err := regState.NodeStatus(nod.ID)
	require.NoError(err, "NodeStatus")
	require.True(status.IsFrozen(), "node should be frozen after slashing")
	require.EqualValues(registry.FreezeForever, status.FreezeEndTime, "node should be frozen forever")
}
