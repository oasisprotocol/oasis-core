package epochtimemock

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
)

// Query is the mock epochtime query interface.
type Query interface {
	Epoch(context.Context) (epochtime.EpochTime, int64, error)
}

// QueryFactory is the mock epochtime query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// QueryAt returns the mock epochtime query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := newImmutableState(ctx, sf.state, height)
	if err != nil {
		return nil, err
	}
	return &epochtimeMockQuerier{state}, nil
}

type epochtimeMockQuerier struct {
	state *immutableState
}

func (eq *epochtimeMockQuerier) Epoch(ctx context.Context) (epochtime.EpochTime, int64, error) {
	return eq.state.getEpoch(ctx)
}

func (app *epochTimeMockApplication) QueryFactory() interface{} {
	return &QueryFactory{app.state}
}

// NewQueryFactory returns a new QueryFactory backed by the given state
// instance.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{state}
}
