package epochtimemock

import (
	"context"

	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

// Query is the mock epochtime query interface.
type Query interface {
	Epoch(context.Context) (epochtime.EpochTime, int64, error)
}

// QueryFactory is the mock epochtime query factory.
type QueryFactory struct {
	app *epochTimeMockApplication
}

// QueryAt returns the mock epochtime query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	var state *immutableState
	var err error
	abciCtx := abci.FromCtx(ctx)

	// If this request was made from InitChain, no blocks and states have been
	// submitted yet, so we use the existing state instead.
	if abciCtx != nil && abciCtx.IsInitChain() {
		state = newMutableState(abciCtx.State()).immutableState
	} else {
		state, err = newImmutableState(sf.app.state, height)
		if err != nil {
			return nil, err
		}
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
	}

	return &epochtimeMockQuerier{state}, nil
}

type epochtimeMockQuerier struct {
	state *immutableState
}

func (eq *epochtimeMockQuerier) Epoch(ctx context.Context) (epochtime.EpochTime, int64, error) {
	return eq.state.getEpoch()
}

func (app *epochTimeMockApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
