package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

func TestChangeParameters(t *testing.T) {
	require := require.New(t)

	// Prepare context.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Setup state.
	state := schedulerState.NewMutableState(ctx.State())
	app := &schedulerApplication{
		state: appState,
	}
	params := &scheduler.ConsensusParameters{
		MinValidators: 1,
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(err, "setting consensus parameters should succeed")

	// Prepare proposal.
	minValidators := 2
	changes := scheduler.ConsensusParameterChanges{
		MinValidators: &minValidators,
	}
	proposal := governance.ChangeParametersProposal{
		Module:  scheduler.ModuleName,
		Changes: cbor.Marshal(changes),
	}

	// Run sub-tests.
	t.Run("happy path - validate only", func(t *testing.T) {
		res, err := app.changeParameters(ctx, &proposal, false)
		require.NoError(err, "validation of consensus parameter changes should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(params.MinValidators, state.MinValidators, "consensus parameters shouldn't change")
	})
	t.Run("happy path - apply changes", func(t *testing.T) {
		res, err := app.changeParameters(ctx, &proposal, true)
		require.NoError(err, "changing consensus parameters should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(minValidators, state.MinValidators, "consensus parameters should change")
	})
	t.Run("invalid proposal", func(t *testing.T) {
		_, err := app.changeParameters(ctx, "proposal", true)
		require.EqualError(err, "tendermint/scheduler: failed to type assert change parameters proposal")
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
			Module: scheduler.ModuleName,
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "tendermint/scheduler: failed to validate consensus parameter changes: consensus parameter changes should not be empty")
	})
}
