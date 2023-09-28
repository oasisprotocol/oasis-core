package roothash

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash/state"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

func TestChangeParameters(t *testing.T) {
	// Prepare context.
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)
	defer ctx.Close()

	// Setup state.
	state := roothashState.NewMutableState(ctx.State())
	app := &rootHashApplication{
		state: appState,
	}
	params := &roothash.ConsensusParameters{
		MaxRuntimeMessages: 10,
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(t, err, "setting consensus parameters should succeed")

	// Prepare proposal.
	maxRuntimeMessages := uint32(20)
	changes := roothash.ConsensusParameterChanges{
		MaxRuntimeMessages: &maxRuntimeMessages,
	}
	proposal := governance.ChangeParametersProposal{
		Module:  roothash.ModuleName,
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
		require.Equal(params.MaxRuntimeMessages, state.MaxRuntimeMessages, "consensus parameters shouldn't change")
	})
	t.Run("happy path - apply changes", func(t *testing.T) {
		require := require.New(t)

		res, err := app.changeParameters(ctx, &proposal, true)
		require.NoError(err, "changing consensus parameters should succeed")
		require.Equal(struct{}{}, res)

		state, err := state.ConsensusParameters(ctx)
		require.NoError(err, "fetching consensus parameters should succeed")
		require.Equal(maxRuntimeMessages, state.MaxRuntimeMessages, "consensus parameters should change")
	})
	t.Run("invalid proposal", func(t *testing.T) {
		require := require.New(t)

		_, err := app.changeParameters(ctx, "proposal", true)
		require.EqualError(err, "roothash: failed to type assert change parameters proposal")
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
			Module: roothash.ModuleName,
		}
		_, err := app.changeParameters(ctx, &proposal, true)
		require.EqualError(err, "roothash: failed to validate consensus parameter changes: consensus parameter changes should not be empty")
	})
}

func initRuntimeGenesisBlock(require *require.Assertions, ctx *abciAPI.Context, id int) (*registry.Runtime, *block.Block) {
	var runtime registry.Runtime
	err := runtime.ID.UnmarshalHex(fmt.Sprintf("8%0*d", 63, id))
	require.NoError(err, "UnmarshalHex")

	blk := block.NewGenesisBlock(runtime.ID, 0)
	err = blk.Header.StateRoot.UnmarshalHex(fmt.Sprintf("%0*d%0*d", 32, id, 32, 1))
	require.NoError(err, "UnmarshalHex")
	err = blk.Header.IORoot.UnmarshalHex(fmt.Sprintf("%0*d%0*d", 32, id, 32, 2))
	require.NoError(err, "UnmarshalHex")

	state := roothashState.NewMutableState(ctx.State())
	err = state.SetRuntimeState(ctx, &roothash.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1,
		LastNormalRound:    0,
		LastNormalHeight:   1,
	})
	require.NoError(err, "SetRuntimeState")

	return &runtime, blk
}

func advanceRuntimeState(require *require.Assertions, ctx *abciAPI.Context, genesisBlock *block.Block, parentBlock *block.Block, runtime *registry.Runtime, round uint64) *block.Block {
	blk := block.NewEmptyBlock(parentBlock, round, block.Normal)

	err := blk.Header.StateRoot.UnmarshalHex(fmt.Sprintf("%s%0*d", runtime.ID.Hex()[:32], 32, round+3))
	require.NoError(err, "UnmarshalHex")
	err = blk.Header.IORoot.UnmarshalHex(fmt.Sprintf("%s%0*d", runtime.ID.Hex()[:32], 32, round+4))
	require.NoError(err, "UnmarshalHex")

	state := roothashState.NewMutableState(ctx.State())
	err = state.SetRuntimeState(ctx, &roothash.RuntimeState{
		Runtime:            runtime,
		GenesisBlock:       genesisBlock,
		CurrentBlock:       blk,
		CurrentBlockHeight: int64(round + 1),
		LastNormalRound:    round,
		LastNormalHeight:   int64(round + 1),
	})
	require.NoError(err, "SetRuntimeState")

	return blk
}

func changeMaxPastRootsStored(require *require.Assertions, app *rootHashApplication, ctx *abciAPI.Context, state *roothashState.MutableState, newMaxPRS uint64) {
	// Prepare proposal for changing the number of roots stored.
	changes := roothash.ConsensusParameterChanges{
		MaxPastRootsStored: &newMaxPRS,
	}
	proposal := governance.ChangeParametersProposal{
		Module:  roothash.ModuleName,
		Changes: cbor.Marshal(changes),
	}

	// Apply proposal.
	res, err := app.changeParameters(ctx, &proposal, true)
	require.NoError(err, "changing consensus parameters should succeed")
	require.Equal(struct{}{}, res)

	cp, err := state.ConsensusParameters(ctx)
	require.NoError(err, "fetching consensus parameters should succeed")
	require.Equal(newMaxPRS, cp.MaxPastRootsStored, "consensus parameters should change")
}

func TestMaxPastRootsStoredMulti(t *testing.T) {
	require := require.New(t)

	// Prepare context.
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)

	// Setup state.
	state := roothashState.NewMutableState(ctx.State())
	_ = &rootHashApplication{
		state: appState,
	}
	params := &roothash.ConsensusParameters{
		MaxPastRootsStored: 2,
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(err, "setting consensus parameters should succeed")

	cp, err := state.ConsensusParameters(ctx)
	require.NoError(err, "fetching consensus parameters should succeed")
	require.EqualValues(2, cp.MaxPastRootsStored, "consensus parameters should have been set")

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextBeginBlock)

	numRuntimes := 10

	// Round 0 (init runtimes, 1 root pair stored).
	rt := make([]*registry.Runtime, numRuntimes)
	genBlk := make([]*block.Block, numRuntimes)
	blk1 := make([]*block.Block, numRuntimes)
	blk2 := make([]*block.Block, numRuntimes)
	for id := 0; id < numRuntimes; id++ {
		rt[id], genBlk[id] = initRuntimeGenesisBlock(require, ctx, id)
	}

	// Make sure that stored past roots are unique between runtimes.
	for a := 0; a < numRuntimes; a++ {
		rtA := rt[a]
		for b := 0; b < numRuntimes; b++ {
			if a == b {
				continue
			}

			rtB := rt[b]

			rootsA, err := state.PastRoundRoots(ctx, rtA.ID)
			require.NoError(err, "PastRoundRoots")
			require.EqualValues(1, len(rootsA))
			require.EqualValues(len(rootsA), state.PastRoundRootsCount(ctx, rtA.ID))
			require.EqualValues(genBlk[a].Header.StateRoot, rootsA[0].StateRoot)
			require.EqualValues(genBlk[a].Header.IORoot, rootsA[0].IORoot)

			rootsB, err := state.PastRoundRoots(ctx, rtB.ID)
			require.NoError(err, "PastRoundRoots")
			require.EqualValues(1, len(rootsB))
			require.EqualValues(len(rootsB), state.PastRoundRootsCount(ctx, rtB.ID))
			require.EqualValues(genBlk[b].Header.StateRoot, rootsB[0].StateRoot)
			require.EqualValues(genBlk[b].Header.IORoot, rootsB[0].IORoot)

			require.NotEqualValues(rootsA[0].StateRoot, rootsB[0].StateRoot)
			require.NotEqualValues(rootsA[0].IORoot, rootsB[0].IORoot)
		}
	}

	// Round 1 (2 root pairs stored).
	for id := 0; id < numRuntimes; id++ {
		blk1[id] = advanceRuntimeState(require, ctx, genBlk[id], genBlk[id], rt[id], 1)
		roots, err := state.PastRoundRoots(ctx, rt[id].ID)
		require.NoError(err, "PastRoundRoots")
		require.EqualValues(2, len(roots))
		require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, rt[id].ID))
		require.EqualValues(genBlk[id].Header.StateRoot, roots[0].StateRoot)
		require.EqualValues(genBlk[id].Header.IORoot, roots[0].IORoot)
		require.EqualValues(blk1[id].Header.StateRoot, roots[1].StateRoot)
		require.EqualValues(blk1[id].Header.IORoot, roots[1].IORoot)

		rfr1, err := state.RoundRoots(ctx, rt[id].ID, 1)
		require.NoError(err, "RoundRoots 1")
		require.EqualValues(blk1[id].Header.StateRoot, rfr1.StateRoot)
		require.EqualValues(blk1[id].Header.IORoot, rfr1.IORoot)
	}

	// Round 2 (2 root pairs stored).
	for id := 0; id < numRuntimes; id++ {
		blk2[id] = advanceRuntimeState(require, ctx, genBlk[id], blk1[id], rt[id], 2)
		roots, err := state.PastRoundRoots(ctx, rt[id].ID)
		require.NoError(err, "PastRoundRoots")
		require.EqualValues(2, len(roots))
		require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, rt[id].ID))
		require.EqualValues(blk1[id].Header.StateRoot, roots[1].StateRoot)
		require.EqualValues(blk1[id].Header.IORoot, roots[1].IORoot)
		require.EqualValues(blk2[id].Header.StateRoot, roots[2].StateRoot)
		require.EqualValues(blk2[id].Header.IORoot, roots[2].IORoot)

		rfr2, err := state.RoundRoots(ctx, rt[id].ID, 2)
		require.NoError(err, "RoundRoots 2")
		require.EqualValues(blk2[id].Header.StateRoot, rfr2.StateRoot)
		require.EqualValues(blk2[id].Header.IORoot, rfr2.IORoot)
	}

	// Verify it again to make sure state didn't get corrupt when advancing.
	for id := 0; id < numRuntimes; id++ {
		roots, err := state.PastRoundRoots(ctx, rt[id].ID)
		require.NoError(err, "PastRoundRoots")
		require.EqualValues(2, len(roots))
		require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, rt[id].ID))
		require.EqualValues(blk1[id].Header.StateRoot, roots[1].StateRoot)
		require.EqualValues(blk1[id].Header.IORoot, roots[1].IORoot)
		require.EqualValues(blk2[id].Header.StateRoot, roots[2].StateRoot)
		require.EqualValues(blk2[id].Header.IORoot, roots[2].IORoot)

		rfr2, err := state.RoundRoots(ctx, rt[id].ID, 2)
		require.NoError(err, "RoundRoots 2")
		require.EqualValues(blk2[id].Header.StateRoot, rfr2.StateRoot)
		require.EqualValues(blk2[id].Header.IORoot, rfr2.IORoot)
	}
}

func TestChangeMaxPastRootsStored(t *testing.T) {
	require := require.New(t)

	// Prepare context.
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock)

	// Setup state.
	state := roothashState.NewMutableState(ctx.State())
	app := &rootHashApplication{
		state: appState,
	}
	params := &roothash.ConsensusParameters{
		MaxPastRootsStored: 2,
	}
	err := state.SetConsensusParameters(ctx, params)
	require.NoError(err, "setting consensus parameters should succeed")

	cp, err := state.ConsensusParameters(ctx)
	require.NoError(err, "fetching consensus parameters should succeed")
	require.EqualValues(2, cp.MaxPastRootsStored, "consensus parameters should have been set")

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextBeginBlock)

	// Round 0 (init, 1 root pair stored).
	runtime, blk := initRuntimeGenesisBlock(require, ctx, 0)

	roots, err := state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(1, len(roots))
	require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk.Header.StateRoot, roots[0].StateRoot)
	require.EqualValues(blk.Header.IORoot, roots[0].IORoot)

	rfr0, err := state.RoundRoots(ctx, runtime.ID, 0)
	require.NoError(err, "RoundRoots 0")
	require.EqualValues(blk.Header.StateRoot, rfr0.StateRoot)
	require.EqualValues(blk.Header.IORoot, rfr0.IORoot)

	// Round 1 (2 root pairs stored).
	blk1 := advanceRuntimeState(require, ctx, blk, blk, runtime, 1)
	roots, err = state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(2, len(roots))
	require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk.Header.StateRoot, roots[0].StateRoot)
	require.EqualValues(blk.Header.IORoot, roots[0].IORoot)
	require.EqualValues(blk1.Header.StateRoot, roots[1].StateRoot)
	require.EqualValues(blk1.Header.IORoot, roots[1].IORoot)

	rfr1, err := state.RoundRoots(ctx, runtime.ID, 1)
	require.NoError(err, "RoundRoots 1")
	require.EqualValues(blk1.Header.StateRoot, rfr1.StateRoot)
	require.EqualValues(blk1.Header.IORoot, rfr1.IORoot)

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextEndBlock)

	// Prepare & apply proposal for reducing the number of roots stored.
	changeMaxPastRootsStored(require, app, ctx, state, 1)

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextBeginBlock)

	// Round 2 (1 root pair stored).
	blk2 := advanceRuntimeState(require, ctx, blk, blk1, runtime, 2)
	roots, err = state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(1, len(roots))
	require.EqualValues(blk2.Header.StateRoot, roots[2].StateRoot)
	require.EqualValues(blk2.Header.IORoot, roots[2].IORoot)

	rfr1, err = state.RoundRoots(ctx, runtime.ID, 1)
	require.NoError(err, "RoundRoots 1")
	require.Nil(rfr1, "roots for round 1 should have been deleted after changing the max")

	// Round 3 (1 root pair stored).
	blk3 := advanceRuntimeState(require, ctx, blk, blk2, runtime, 3)
	roots, err = state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(1, len(roots))
	require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk3.Header.StateRoot, roots[3].StateRoot)
	require.EqualValues(blk3.Header.IORoot, roots[3].IORoot)

	rfr2, err := state.RoundRoots(ctx, runtime.ID, 2)
	require.NoError(err, "RoundRoots 2")
	require.Nil(rfr2, "roots for round 2 should have been deleted in round 3")

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextEndBlock)

	// Prepare & apply proposal for increasing the number of roots stored.
	changeMaxPastRootsStored(require, app, ctx, state, 2)

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextBeginBlock)

	// Round 4 (2 root pairs stored).
	blk4 := advanceRuntimeState(require, ctx, blk, blk3, runtime, 4)
	roots, err = state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(2, len(roots))
	require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk3.Header.StateRoot, roots[3].StateRoot)
	require.EqualValues(blk3.Header.IORoot, roots[3].IORoot)
	require.EqualValues(blk4.Header.StateRoot, roots[4].StateRoot)
	require.EqualValues(blk4.Header.IORoot, roots[4].IORoot)

	// Round 5 (2 root pairs stored).
	blk5 := advanceRuntimeState(require, ctx, blk, blk4, runtime, 5)
	roots, err = state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(2, len(roots))
	require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk4.Header.StateRoot, roots[4].StateRoot)
	require.EqualValues(blk4.Header.IORoot, roots[4].IORoot)
	require.EqualValues(blk5.Header.StateRoot, roots[5].StateRoot)
	require.EqualValues(blk5.Header.IORoot, roots[5].IORoot)

	rfr3, err := state.RoundRoots(ctx, runtime.ID, 3)
	require.NoError(err, "RoundRoots 3")
	require.Nil(rfr3, "roots for round 3 should have been deleted in round 5")

	// Round 6 (2 root pairs stored).
	blk6 := advanceRuntimeState(require, ctx, blk, blk5, runtime, 6)
	roots, err = state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(2, len(roots))
	require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, runtime.ID))
	require.EqualValues(blk5.Header.StateRoot, roots[5].StateRoot)
	require.EqualValues(blk5.Header.IORoot, roots[5].IORoot)
	require.EqualValues(blk6.Header.StateRoot, roots[6].StateRoot)
	require.EqualValues(blk6.Header.IORoot, roots[6].IORoot)

	rfr4, err := state.RoundRoots(ctx, runtime.ID, 4)
	require.NoError(err, "RoundRoots 4")
	require.Nil(rfr4, "roots for round 4 should have been deleted in round 6")

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextEndBlock)

	// Prepare & apply proposal for disabling storing the roots.
	changeMaxPastRootsStored(require, app, ctx, state, 0)

	// Switch context.
	ctx.Close()
	ctx = appState.NewContext(abciAPI.ContextBeginBlock)

	// Round 7 (0 root pairs stored).
	_ = advanceRuntimeState(require, ctx, blk, blk6, runtime, 7)
	roots, err = state.PastRoundRoots(ctx, runtime.ID)
	require.NoError(err, "PastRoundRoots")
	require.EqualValues(0, len(roots))
	require.EqualValues(len(roots), state.PastRoundRootsCount(ctx, runtime.ID))

	rfr7, err := state.RoundRoots(ctx, runtime.ID, 7)
	require.NoError(err, "RoundRoots 7")
	require.Nil(rfr7, "roots for round 7 should not exist")

	ctx.Close()
}
