package state

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
)

func TestConsensusParameters(t *testing.T) {
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextInitChain)
	defer ctx.Close()

	st := NewMutableState(ctx.State())

	// Prepare.
	params := churp.ConsensusParameters{
		GasCosts: transaction.Costs{
			churp.GasOpCreate: 1000,
		},
	}

	// Empty state.
	_, err := st.ConsensusParameters(ctx)
	require.Error(t, err)

	// Set state.
	err = st.SetConsensusParameters(ctx, &params)
	require.NoError(t, err)

	// New state.
	fetched, err := st.ConsensusParameters(ctx)
	require.NoError(t, err)
	require.Len(t, fetched.GasCosts, 1)
	require.Equal(t, params.GasCosts[churp.GasOpCreate], fetched.GasCosts[churp.GasOpCreate])

	// Update state.
	params.GasCosts[churp.GasOpCreate] = 2000
	err = st.SetConsensusParameters(ctx, &params)
	require.NoError(t, err)

	// Updated state.
	fetched, err = st.ConsensusParameters(ctx)
	require.NoError(t, err)
	require.Len(t, fetched.GasCosts, 1)
	require.Equal(t, params.GasCosts[churp.GasOpCreate], fetched.GasCosts[churp.GasOpCreate])
}

func TestStatus(t *testing.T) {
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock)
	defer ctx.Close()

	st := NewMutableState(ctx.State())

	// Prepare.
	status := &churp.Status{
		Identity: churp.Identity{
			ID:        1,
			RuntimeID: common.NewTestNamespaceFromSeed([]byte{1}, common.NamespaceTest),
		},
		Threshold: 1,
	}

	// Empty state.
	_, err := st.Status(ctx, status.RuntimeID, status.ID)
	require.Error(t, err)

	// Set state.
	err = st.SetStatus(ctx, status)
	require.NoError(t, err)

	// New state.
	fetched, err := st.Status(ctx, status.RuntimeID, status.ID)
	require.NoError(t, err)
	require.Equal(t, status, fetched)

	// Update state.
	status.Threshold = 2
	err = st.SetStatus(ctx, status)
	require.NoError(t, err)

	// Updated state.
	fetched, err = st.Status(ctx, status.RuntimeID, status.ID)
	require.NoError(t, err)
	require.Equal(t, status, fetched)
}

func TestStatuses(t *testing.T) {
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock)
	defer ctx.Close()

	st := NewMutableState(ctx.State())

	// Prepare.
	statuses := []*churp.Status{
		{
			Identity: churp.Identity{
				ID:        1,
				RuntimeID: common.NewTestNamespaceFromSeed([]byte{1}, common.NamespaceTest),
			},
			Threshold: 1,
		},
		{
			Identity: churp.Identity{
				ID:        2,
				RuntimeID: common.NewTestNamespaceFromSeed([]byte{1}, common.NamespaceTest),
			},
			Threshold: 2,
		},
		{
			Identity: churp.Identity{
				ID:        1,
				RuntimeID: common.NewTestNamespaceFromSeed([]byte{2}, common.NamespaceTest),
			},
			Threshold: 1,
		},
	}

	// Empty state.
	fetched, err := st.Statuses(ctx, statuses[0].RuntimeID)
	require.NoError(t, err)
	require.Empty(t, fetched)

	// Set state.
	for _, status := range statuses {
		err = st.SetStatus(ctx, status)
		require.NoError(t, err)
	}

	// New state.
	fetched, err = st.Statuses(ctx, statuses[0].RuntimeID)
	require.NoError(t, err)
	require.ElementsMatch(t, statuses[:2], fetched)
}

func TestAllStatuses(t *testing.T) {
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock)
	defer ctx.Close()

	st := NewMutableState(ctx.State())

	// Prepare.
	statuses := []*churp.Status{
		{
			Identity: churp.Identity{
				ID:        1,
				RuntimeID: common.NewTestNamespaceFromSeed([]byte{1}, common.NamespaceTest),
			},
			Threshold: 1,
		},
		{
			Identity: churp.Identity{
				ID:        2,
				RuntimeID: common.NewTestNamespaceFromSeed([]byte{1}, common.NamespaceTest),
			},
			Threshold: 2,
		},
		{
			Identity: churp.Identity{
				ID:        1,
				RuntimeID: common.NewTestNamespaceFromSeed([]byte{2}, common.NamespaceTest),
			},
			Threshold: 1,
		},
	}

	// Empty state.
	fetched, err := st.AllStatuses(ctx)
	require.NoError(t, err)
	require.Empty(t, fetched)

	// Set state.
	for _, status := range statuses {
		err = st.SetStatus(ctx, status)
		require.NoError(t, err)
	}

	// New state.
	fetched, err = st.AllStatuses(ctx)
	require.NoError(t, err)
	require.ElementsMatch(t, statuses, fetched)
}
