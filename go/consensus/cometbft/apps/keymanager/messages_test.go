package keymanager

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
)

func TestChangeParameters(t *testing.T) {
	// Prepare context.
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	// Setup state.
	state := secretsState.NewMutableState(ctx.State())
	app := &keymanagerApplication{
		state: appState,
	}
	params := &secrets.ConsensusParameters{
		GasCosts: transaction.Costs{
			secrets.GasOpUpdatePolicy: 1000,
		},
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(t, err, "setting consensus parameters should succeed")

	// Prepare proposal.
	gasCosts := transaction.Costs{
		secrets.GasOpUpdatePolicy: 2000,
	}
	changes := secrets.ConsensusParameterChanges{
		GasCosts: gasCosts,
	}
	proposal := governance.ChangeParametersProposal{
		Module:  keymanager.ModuleName,
		Changes: cbor.Marshal(changes),
	}

	// Run sub-tests.
	t.Run("happy path - validate only", func(t *testing.T) {
		require := require.New(t)

		res, err := app.changeParameters(ctx, &proposal, false)
		require.NoError(err, "validation of consensus parameter changes should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(params.GasCosts, state.GasCosts, "consensus parameters shouldn't change")
	})
	t.Run("happy path - apply changes", func(t *testing.T) {
		require := require.New(t)

		res, err := app.changeParameters(ctx, &proposal, true)
		require.NoError(err, "changing consensus parameters should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(gasCosts, state.GasCosts, "consensus parameters should change")
	})
	t.Run("invalid proposal", func(t *testing.T) {
		require := require.New(t)

		_, err := app.changeParameters(ctx, "proposal", true)
		require.EqualError(err, "keymanager: failed to type assert change parameters proposal")
	})
	t.Run("different module", func(t *testing.T) {
		require := require.New(t)

		proposal := governance.ChangeParametersProposal{
			Module: "module",
		}
		res, err := app.changeParameters(ctx, &proposal, true)
		require.Nil(res, "changes for other modules should be ignored")
		require.NoError(err, "changes for other modules should be ignored without error")
	})
	t.Run("empty changes", func(t *testing.T) {
		require := require.New(t)

		proposal := governance.ChangeParametersProposal{
			Module: keymanager.ModuleName,
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "keymanager: failed to validate consensus parameter changes: consensus parameter changes should not be empty")
	})
}
