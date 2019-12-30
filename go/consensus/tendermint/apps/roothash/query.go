package roothash

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	roothashState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash/state"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
)

// Query is the roothash query interface.
type Query interface {
	LatestBlock(context.Context, common.Namespace) (*block.Block, error)
	GenesisBlock(context.Context, common.Namespace) (*block.Block, error)
	Genesis(context.Context) (*roothash.Genesis, error)
}

// QueryFactory is the roothash query factory.
type QueryFactory struct {
	app *rootHashApplication
}

// QueryAt returns the roothash query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	var state *roothashState.ImmutableState
	var err error
	abciCtx := abci.FromCtx(ctx)

	// If this request was made from InitChain, no blocks and states have been
	// submitted yet, so we use the existing state instead.
	if abciCtx != nil && abciCtx.IsInitChain() {
		state = roothashState.NewMutableState(abciCtx.State()).ImmutableState
	} else {
		state, err = roothashState.NewImmutableState(sf.app.state, height)
		if err != nil {
			return nil, err
		}
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
	}

	return &rootHashQuerier{state}, nil
}

type rootHashQuerier struct {
	state *roothashState.ImmutableState
}

func (rq *rootHashQuerier) LatestBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := rq.state.RuntimeState(id)
	if err != nil {
		return nil, err
	}
	return runtime.CurrentBlock, nil
}

func (rq *rootHashQuerier) GenesisBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := rq.state.RuntimeState(id)
	if err != nil {
		return nil, err
	}
	return runtime.GenesisBlock, nil
}

func (app *rootHashApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
