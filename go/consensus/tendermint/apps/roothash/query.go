package roothash

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
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
	state, err := roothashState.NewImmutableState(ctx, sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &rootHashQuerier{state}, nil
}

type rootHashQuerier struct {
	state *roothashState.ImmutableState
}

func (rq *rootHashQuerier) LatestBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := rq.state.RuntimeState(ctx, id)
	if err != nil {
		return nil, err
	}
	return runtime.CurrentBlock, nil
}

func (rq *rootHashQuerier) GenesisBlock(ctx context.Context, id common.Namespace) (*block.Block, error) {
	runtime, err := rq.state.RuntimeState(ctx, id)
	if err != nil {
		return nil, err
	}
	return runtime.GenesisBlock, nil
}

func (app *rootHashApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
