package registry

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func TestChangeParameters(t *testing.T) {
	// Prepare context.
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	// Setup state.
	state := registryState.NewMutableState(ctx.State())
	app := &registryApplication{
		state: appState,
	}
	params := &registry.ConsensusParameters{
		MaxNodeExpiration: 10,
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(t, err, "setting consensus parameters should succeed")

	// Prepare proposal.
	maxNodeExpiration := uint64(20)
	changes := registry.ConsensusParameterChanges{
		MaxNodeExpiration: &maxNodeExpiration,
	}
	proposal := governance.ChangeParametersProposal{
		Module:  registry.ModuleName,
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
		require.Equal(params.MaxNodeExpiration, state.MaxNodeExpiration, "consensus parameters shouldn't change")
	})
	t.Run("happy path - apply changes", func(t *testing.T) {
		require := require.New(t)

		res, err := app.changeParameters(ctx, &proposal, true)
		require.NoError(err, "changing consensus parameters should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(maxNodeExpiration, state.MaxNodeExpiration, "consensus parameters should change")
	})
	t.Run("invalid proposal", func(t *testing.T) {
		require := require.New(t)

		_, err := app.changeParameters(ctx, "proposal", true)
		require.EqualError(err, "registry: failed to type assert change parameters proposal")
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
			Module: registry.ModuleName,
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "registry: failed to validate consensus parameter changes: consensus parameter changes should not be empty")
	})
	t.Run("invalid changes", func(t *testing.T) {
		require := require.New(t)

		var maxNodeExpiration uint64
		changes := registry.ConsensusParameterChanges{
			MaxNodeExpiration: &maxNodeExpiration,
		}
		proposal := governance.ChangeParametersProposal{
			Module:  registry.ModuleName,
			Changes: cbor.Marshal(changes),
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "registry: failed to validate consensus parameters: maximum node expiration not specified")
	})
}
