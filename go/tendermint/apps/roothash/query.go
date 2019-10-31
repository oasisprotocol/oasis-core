package roothash

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/tendermint/abci"
	roothashState "github.com/oasislabs/oasis-core/go/tendermint/apps/roothash/state"
)

// Query is the roothash query interface.
type Query interface {
	LatestBlock(context.Context, signature.PublicKey) (*block.Block, error)
	GenesisBlock(context.Context, signature.PublicKey) (*block.Block, error)
	Genesis(context.Context) (*roothash.Genesis, error)
}

// QueryFactory is the roothash query factory.
type QueryFactory struct {
	app *rootHashApplication
}

// QueryAt returns the roothash query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := roothashState.NewImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx := abci.FromCtx(ctx); abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
	}
	return &rootHashQuerier{state}, nil
}

type rootHashQuerier struct {
	state *roothashState.ImmutableState
}

func (rq *rootHashQuerier) LatestBlock(ctx context.Context, id signature.PublicKey) (*block.Block, error) {
	runtime, err := rq.state.RuntimeState(id)
	if err != nil {
		return nil, err
	}
	if runtime == nil {
		return nil, errNoSuchRuntime
	}

	return runtime.CurrentBlock, nil
}

func (rq *rootHashQuerier) GenesisBlock(ctx context.Context, id signature.PublicKey) (*block.Block, error) {
	runtime, err := rq.state.RuntimeState(id)
	if err != nil {
		return nil, err
	}
	if runtime == nil {
		return nil, errNoSuchRuntime
	}

	return runtime.GenesisBlock, nil
}

func (app *rootHashApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
