package roothash

import (
	"context"

	"github.com/tendermint/tendermint/abci/types"

	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	registryState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/registry/state"
	genesisApi "github.com/oasislabs/oasis-core/go/genesis/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
)

func (app *rootHashApplication) InitChain(ctx *abci.Context, request types.RequestInitChain, doc *genesisApi.Document) error {
	st := doc.RootHash

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
	return &roothash.Genesis{}, nil
}
