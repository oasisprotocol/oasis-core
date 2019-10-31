package roothash

import (
	"context"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	genesis "github.com/oasislabs/oasis-core/go/genesis/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/tendermint/apps/registry/state"
	roothashState "github.com/oasislabs/oasis-core/go/tendermint/apps/roothash/state"
)

func (app *rootHashApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesis.Document) error {
	st := doc.RootHash

	// Store initial round timeout from the genesis document.
	rhState := roothashState.NewMutableState(ctx.State())
	rhState.SetConsensusParameters(&st.Parameters)

	// The per-runtime roothash state is done primarily via DeliverTx, but
	// also needs to be done here since the genesis state can have runtime
	// registrations.
	//
	// Note: This could use the genesis state, but the registry has already
	// carved out it's entries by this point.

	regState := registryState.NewMutableState(ctx.State())
	runtimes, _ := regState.Runtimes()
	for _, v := range runtimes {
		app.logger.Info("InitChain: allocating per-runtime state",
			"runtime", v.ID,
		)
		app.onNewRuntime(ctx, v, &st)
	}

	return nil
}

func (rq *rootHashQuerier) Genesis(ctx context.Context) (*roothash.Genesis, error) {
	runtimes := rq.state.Runtimes()

	// Get per-runtime blocks.
	blocks := make(map[signature.MapKey]*block.Block)
	for _, rt := range runtimes {
		blocks[rt.Runtime.ID.ToMapKey()] = rt.CurrentBlock
	}

	params, err := rq.state.ConsensusParameters()
	if err != nil {
		return nil, err
	}

	genesis := &roothash.Genesis{
		Parameters: *params,
		Blocks:     blocks,
	}
	return genesis, nil
}
