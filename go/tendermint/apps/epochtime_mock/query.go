package epochtimemock

import (
	"context"

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
func (sf *QueryFactory) QueryAt(height int64) (Query, error) {
	state, err := newImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
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
