package governance

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	governanceState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/governance/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
)

func TestChangeParameters(t *testing.T) {
	require := require.New(t)

	// Prepare context.
	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Setup state.
	state := governanceState.NewMutableState(ctx.State())
	app := &governanceApplication{
		state: appState,
	}
	params := &governance.ConsensusParameters{
		StakeThreshold:            90,
		UpgradeCancelMinEpochDiff: beacon.EpochTime(100),
		UpgradeMinEpochDiff:       beacon.EpochTime(100),
		VotingPeriod:              beacon.EpochTime(50),
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(err, "setting consensus parameters should succeed")

	// Prepare proposal.
	votingPeriod := beacon.EpochTime(60)
	changes := governance.ConsensusParameterChanges{
		VotingPeriod: &votingPeriod,
	}
	proposal := governance.ChangeParametersProposal{
		Module:  governance.ModuleName,
		Changes: cbor.Marshal(changes),
	}

	// Run sub-tests.
	t.Run("happy path - validate only", func(t *testing.T) {
		res, err := app.changeParameters(ctx, &proposal, false)
		require.NoError(err, "validation of consensus parameter changes should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(params.VotingPeriod, state.VotingPeriod, "consensus parameters shouldn't change")
	})
	t.Run("happy path - apply changes", func(t *testing.T) {
		res, err := app.changeParameters(ctx, &proposal, true)
		require.NoError(err, "changing consensus parameters should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(votingPeriod, state.VotingPeriod, "consensus parameters should change")
	})
	t.Run("invalid proposal", func(t *testing.T) {
		_, err := app.changeParameters(ctx, "proposal", true)
		require.EqualError(err, "tendermint/governance: failed to type assert change parameters proposal")
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
			Module: governance.ModuleName,
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "tendermint/governance: failed to validate consensus parameter changes: consensus parameter changes should not be empty")
	})
	t.Run("invalid changes", func(t *testing.T) {
		votingPeriod := beacon.EpochTime(100)
		changes := governance.ConsensusParameterChanges{
			VotingPeriod: &votingPeriod,
		}
		proposal := governance.ChangeParametersProposal{
			Module:  governance.ModuleName,
			Changes: cbor.Marshal(changes),
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "tendermint/governance: failed to validate consensus parameters: voting_period should be less than upgrade_min_epoch_diff")
	})
}
