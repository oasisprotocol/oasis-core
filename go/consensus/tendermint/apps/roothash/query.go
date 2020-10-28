package roothash

import (
	"context"

	"github.com/oasisprotocol/oasis-core/go/common"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
)

// Query is the roothash query interface.
type Query interface {
	LatestBlock(context.Context, common.Namespace) (*block.Block, error)
	GenesisBlock(context.Context, common.Namespace) (*block.Block, error)
	RuntimeState(context.Context, common.Namespace) (*roothash.RuntimeState, error)
	Genesis(context.Context) (*roothash.Genesis, error)
}

// QueryFactory is the roothash query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the roothash query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := roothashState.NewImmutableState(ctx, sf.state, height)
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

func (rq *rootHashQuerier) RuntimeState(ctx context.Context, id common.Namespace) (*roothash.RuntimeState, error) {
	return rq.state.RuntimeState(ctx, id)
}

func (app *rootHashApplication) QueryFactory() interface{} {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
