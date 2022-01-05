package roothash

import (
	"context"
	"fmt"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	genesisAPI "github.com/oasisprotocol/oasis-core/go/genesis/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothashAPI "github.com/oasisprotocol/oasis-core/go/roothash/api"
)

func (app *rootHashApplication) InitChain(ctx *abciAPI.Context, request types.RequestInitChain, doc *genesisAPI.Document) error {
	st := doc.RootHash

	state := roothashState.NewMutableState(ctx.State())
	if err := state.SetConsensusParameters(ctx, &st.Parameters); err != nil {
		return fmt.Errorf("failed to set consensus parameters: %w", err)
	}

	// The per-runtime roothash state is done primarily via DeliverTx, but
	// also needs to be done here since the genesis state can have runtime
	// registrations.
	//
	// Note: This could use the genesis state, but the registry has already
	// carved out it's entries by this point.

	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes(ctx)
	for _, v := range runtimes {
		ctx.Logger().Info("InitChain: allocating per-runtime state",
			"runtime", v.ID,
		)
		if err := app.onNewRuntime(ctx, v, &st, false); err != nil {
			return fmt.Errorf("failed to initialize runtime %s state: %w", v.ID, err)
		}
	}
	suspendedRuntimes, _ := regState.SuspendedRuntimes(ctx)
	for _, v := range suspendedRuntimes {
		ctx.Logger().Info("InitChain: allocating per-runtime state",
			"runtime", v.ID,
		)
		if err := app.onNewRuntime(ctx, v, &st, true); err != nil {
			return fmt.Errorf("failed to initialize (suspended) runtime %s state: %w", v.ID, err)
		}
	}

	return nil
}

func (rq *rootHashQuerier) Genesis(ctx context.Context) (*roothashAPI.Genesis, error) {
	runtimes, err := rq.state.Runtimes(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch runtimes: %w", err)
	}

	// Get per-runtime states.
	rtStates := make(map[common.Namespace]*roothashAPI.GenesisRuntimeState)
	for _, rt := range runtimes {
		var lastRoundResults *roothashAPI.RoundResults
		lastRoundResults, err = rq.LastRoundResults(ctx, rt.Runtime.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch last round results for runtime '%s': %w", rt.Runtime.ID, err)
		}

		rtState := roothashAPI.GenesisRuntimeState{
			RuntimeGenesis: registryAPI.RuntimeGenesis{
				StateRoot: rt.CurrentBlock.Header.StateRoot,
				Round:     rt.CurrentBlock.Header.Round,
			},
			MessageResults: lastRoundResults.Messages,
		}

		rtStates[rt.Runtime.ID] = &rtState
	}

	params, err := rq.state.ConsensusParameters(ctx)
	if err != nil {
		return nil, err
	}

	genesis := &roothashAPI.Genesis{
		Parameters:    *params,
		RuntimeStates: rtStates,
	}
	return genesis, nil
}
