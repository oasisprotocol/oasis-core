package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

func TestEvidence(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	s := NewMutableState(ctx.State())

	rt1ID := common.NewTestNamespaceFromSeed([]byte("apps/roothash/state_test: runtime1"), 0)
	rt2ID := common.NewTestNamespaceFromSeed([]byte("apps/roothash/state_test: runtime2"), 0)
	rt3ID := common.NewTestNamespaceFromSeed([]byte("apps/roothash/state_test: runtime3"), 0)

	for _, ev := range []struct {
		ns common.Namespace
		r  uint64
		ev api.Evidence
	}{
		{
			rt1ID,
			0,
			api.Evidence{
				EquivocationExecutor: &api.EquivocationExecutorEvidence{},
			},
		},
		{
			rt1ID,
			10,
			api.Evidence{
				EquivocationProposal: &api.EquivocationProposalEvidence{},
			},
		},
		{
			rt1ID,
			20,
			api.Evidence{
				EquivocationExecutor: &api.EquivocationExecutorEvidence{},
			},
		},
		{
			rt2ID,
			5,
			api.Evidence{
				EquivocationExecutor: &api.EquivocationExecutorEvidence{},
			},
		},
		{
			rt2ID,
			10,
			api.Evidence{
				EquivocationProposal: &api.EquivocationProposalEvidence{},
			},
		},
		{
			rt2ID,
			20,
			api.Evidence{
				EquivocationExecutor: &api.EquivocationExecutorEvidence{},
			},
		},
	} {
		h, err := ev.ev.Hash()
		require.NoError(err, "ev.Hash()", ev.ev)
		err = s.SetEvidenceHash(ctx, ev.ns, ev.r, h)
		require.NoError(err, "SetEvidenceHash()", ev)
		b, err := s.EvidenceHashExists(ctx, ev.ns, ev.r, h)
		require.NoError(err, "EvidenceHashExists", ev)
		require.True(b, "EvidenceHashExists", ev)
	}

	ev := api.Evidence{
		EquivocationExecutor: &api.EquivocationExecutorEvidence{},
	}
	h, err := ev.Hash()
	require.NoError(err, "ev.Hash()")
	b, err := s.EvidenceHashExists(ctx, rt1ID, 5, h)
	require.NoError(err, "EvidenceHashExists")
	require.False(b, "Evidence hash should not exist")

	b, err = s.EvidenceHashExists(ctx, rt2ID, 5, h)
	require.NoError(err, "EvidenceHashExists")
	require.True(b, "Evidence hash should exist")

	// Expire evidence.
	err = s.RemoveExpiredEvidence(ctx, rt1ID, 10)
	require.NoError(err, "RemoveExpiredEvidence")
	err = s.RemoveExpiredEvidence(ctx, rt2ID, 10)
	require.NoError(err, "RemoveExpiredEvidence")
	err = s.RemoveExpiredEvidence(ctx, rt3ID, 1)
	require.NoError(err, "RemoveExpiredEvidence")

	b, err = s.EvidenceHashExists(ctx, rt2ID, 5, h)
	require.NoError(err, "EvidenceHashExists")
	require.False(b, "Expired evidence hash should not exist anymore")

	b, err = s.EvidenceHashExists(ctx, rt1ID, 20, h)
	require.NoError(err, "EvidenceHashExists")
	require.True(b, "Not expired evidence hash should still exist")
}

func TestSeparateRuntimeRoots(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock, now)
	defer ctx.Close()

	st := NewMutableState(ctx.State())

	var runtime registry.Runtime
	err := runtime.ID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(err, "UnmarshalHex")

	blk := block.NewGenesisBlock(runtime.ID, 0)
	err = blk.Header.StateRoot.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(err, "UnmarshalHex")
	err = blk.Header.IORoot.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000002")
	require.NoError(err, "UnmarshalHex")
	err = st.SetRuntimeState(ctx, &api.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1,
		LastNormalRound:    0,
		LastNormalHeight:   1,
	})
	require.NoError(err, "SetRuntimeState")

	stateRoot, err := st.StateRoot(ctx, runtime.ID)
	require.NoError(err, "StateRoot")
	require.EqualValues(blk.Header.StateRoot, stateRoot)

	ioRoot, err := st.IORoot(ctx, runtime.ID)
	require.NoError(err, "IORoot")
	require.EqualValues(blk.Header.IORoot, ioRoot)
}
