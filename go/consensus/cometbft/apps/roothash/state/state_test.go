package state

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

func TestEvidence(t *testing.T) {
	require := require.New(t)

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextBeginBlock)
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

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})

	ctx := appState.NewContext(abciAPI.ContextInitChain)
	st := NewMutableState(ctx.State())
	err := st.SetConsensusParameters(ctx, &api.ConsensusParameters{})
	require.NoError(err, "SetConsensusParameters")
	ctx.Close()

	ctx = appState.NewContext(abciAPI.ContextBeginBlock)
	defer ctx.Close()

	st = NewMutableState(ctx.State())

	var runtime registry.Runtime
	err = runtime.ID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
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

func TestPastRuntimeRoots(t *testing.T) {
	require := require.New(t)

	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})

	// Set the consensus parameters.
	initCtx := appState.NewContext(abciAPI.ContextInitChain)
	st := NewMutableState(initCtx.State())
	params := &api.ConsensusParameters{
		MaxPastRootsStored: 2,
	}
	require.NoError(st.SetConsensusParameters(initCtx, params), "SetConsensusParameters")
	initCtx.Close()

	// Do the test.
	ctx := appState.NewContext(abciAPI.ContextBeginBlock)
	defer ctx.Close()
	st = NewMutableState(ctx.State())

	// Round 0.
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

	roots, err := st.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(1, len(roots))
	require.EqualValues(len(roots), st.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk.Header.StateRoot, roots[0].StateRoot)
	require.EqualValues(blk.Header.IORoot, roots[0].IORoot)

	rfr0, err := st.RoundRoots(ctx, runtime.ID, 0)
	require.NoError(err, "RoundRoots 0")
	require.EqualValues(blk.Header.StateRoot, rfr0.StateRoot)
	require.EqualValues(blk.Header.IORoot, rfr0.IORoot)

	rfr1, err := st.RoundRoots(ctx, runtime.ID, 1)
	require.NoError(err, "RoundRoots 1")
	require.Nil(rfr1, "round 1 hasn't happened yet, so there should be no roots for it yet")

	// Round 1.
	blk1 := block.NewEmptyBlock(blk, 1, block.Normal)
	err = blk1.Header.StateRoot.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000003")
	require.NoError(err, "UnmarshalHex")
	err = blk1.Header.IORoot.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000004")
	require.NoError(err, "UnmarshalHex")
	err = st.SetRuntimeState(ctx, &api.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk1,
		CurrentBlockHeight: 2,
		LastNormalRound:    1,
		LastNormalHeight:   2,
	})
	require.NoError(err, "SetRuntimeState")

	roots, err = st.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(2, len(roots))
	require.EqualValues(len(roots), st.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk.Header.StateRoot, roots[0].StateRoot)
	require.EqualValues(blk.Header.IORoot, roots[0].IORoot)
	require.EqualValues(blk1.Header.StateRoot, roots[1].StateRoot)
	require.EqualValues(blk1.Header.IORoot, roots[1].IORoot)

	rfr1, err = st.RoundRoots(ctx, runtime.ID, 1)
	require.NoError(err, "RoundRoots 1")
	require.EqualValues(rfr1.StateRoot, roots[1].StateRoot)
	require.EqualValues(rfr1.IORoot, roots[1].IORoot)

	// Round 2.
	blk2 := block.NewEmptyBlock(blk1, 2, block.Normal)
	err = blk2.Header.StateRoot.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000005")
	require.NoError(err, "UnmarshalHex")
	err = blk2.Header.IORoot.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000006")
	require.NoError(err, "UnmarshalHex")
	err = st.SetRuntimeState(ctx, &api.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk2,
		CurrentBlockHeight: 3,
		LastNormalRound:    2,
		LastNormalHeight:   3,
	})
	require.NoError(err, "SetRuntimeState")

	roots, err = st.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(2, len(roots))
	require.EqualValues(len(roots), st.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk1.Header.StateRoot, roots[1].StateRoot)
	require.EqualValues(blk1.Header.IORoot, roots[1].IORoot)
	require.EqualValues(blk2.Header.StateRoot, roots[2].StateRoot)
	require.EqualValues(blk2.Header.IORoot, roots[2].IORoot)

	// Reduce max space for roots to 1 -- only the older root should be removed.
	err = st.ShrinkPastRoots(ctx, 1)
	require.NoError(err, "ShrinkPastRoots 1")

	roots, err = st.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(1, len(roots))
	require.EqualValues(len(roots), st.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk2.Header.StateRoot, roots[2].StateRoot)
	require.EqualValues(blk2.Header.IORoot, roots[2].IORoot)

	// Increase it back to 2 -- the existing root should remain.
	err = st.ShrinkPastRoots(ctx, 2)
	require.NoError(err, "ShrinkPastRoots 2")

	roots, err = st.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(1, len(roots))
	require.EqualValues(len(roots), st.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk2.Header.StateRoot, roots[2].StateRoot)
	require.EqualValues(blk2.Header.IORoot, roots[2].IORoot)

	// Now reduce it to 0 -- no roots should remain.
	err = st.ShrinkPastRoots(ctx, 0)
	require.NoError(err, "ShrinkPastRoots 0")

	roots, err = st.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(0, len(roots))
	require.EqualValues(len(roots), st.PastRoundRootsCount(ctx, runtime.ID))
}
