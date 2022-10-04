package staking

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	stakingState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/staking/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

func TestChangeParameters(t *testing.T) {
	require := require.New(t)

	// Prepare context.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Setup state.
	state := stakingState.NewMutableState(ctx.State())
	app := &stakingApplication{
		state: appState,
	}
	params := &staking.ConsensusParameters{
		Thresholds: map[staking.ThresholdKind]quantity.Quantity{
			staking.KindEntity:            *quantity.NewFromUint64(1),
			staking.KindNodeValidator:     *quantity.NewFromUint64(1),
			staking.KindNodeCompute:       *quantity.NewFromUint64(1),
			staking.KindNodeKeyManager:    *quantity.NewFromUint64(1),
			staking.KindRuntimeCompute:    *quantity.NewFromUint64(1),
			staking.KindRuntimeKeyManager: *quantity.NewFromUint64(1),
		},
		FeeSplitWeightVote: *quantity.NewFromUint64(1),
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(err, "setting consensus parameters should succeed")

	// Prepare proposal.
	feeSplitWeightVote := quantity.NewFromUint64(2)
	changes := staking.ConsensusParameterChanges{
		FeeSplitWeightVote: feeSplitWeightVote,
	}
	proposal := governance.ChangeParametersProposal{
		Module:  staking.ModuleName,
		Changes: cbor.Marshal(changes),
	}

	// Run sub-tests.
	t.Run("happy path - validate only", func(t *testing.T) {
		res, err := app.changeParameters(ctx, &proposal, false)
		require.NoError(err, "validation of consensus parameter changes should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(params.FeeSplitWeightVote, state.FeeSplitWeightVote, "consensus parameters shouldn't change")
	})
	t.Run("happy path - apply changes", func(t *testing.T) {
		res, err := app.changeParameters(ctx, &proposal, true)
		require.NoError(err, "changing consensus parameters should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(*feeSplitWeightVote, state.FeeSplitWeightVote, "consensus parameters should change")
	})
	t.Run("invalid proposal", func(t *testing.T) {
		_, err := app.changeParameters(ctx, "proposal", true)
		require.EqualError(err, "staking: failed to type assert change parameters proposal")
	})
	t.Run("different module", func(t *testing.T) {
		proposal := governance.ChangeParametersProposal{
			Module: "module",
		}
		res, err := app.changeParameters(ctx, &proposal, true)
		require.Nil(res, "changes for other modules should be ignored")
		require.NoError(err, "changes for other modules should be ignored without error")
	})
	t.Run("empty changes", func(t *testing.T) {
		proposal := governance.ChangeParametersProposal{
			Module: staking.ModuleName,
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "staking: failed to validate consensus parameter changes: consensus parameter changes should not be empty")
	})
	t.Run("invalid changes", func(t *testing.T) {
		var feeSplitWeightVote quantity.Quantity
		changes := staking.ConsensusParameterChanges{
			FeeSplitWeightVote: &feeSplitWeightVote,
		}
		proposal := governance.ChangeParametersProposal{
			Module:  staking.ModuleName,
			Changes: cbor.Marshal(changes),
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "staking: failed to validate consensus parameters: fee split proportions are all zero")
	})
}
