package beacon

import (
	"context"

	beaconState "github.com/oasislabs/oasis-core/go/tendermint/apps/beacon/state"
)

// Query is the beacon query interface.
type Query interface {
	Beacon(context.Context) ([]byte, error)
}

// QueryFactory is the beacon query factory.
type QueryFactory struct {
	app *beaconApplication
}

// QueryAt returns the beacon query interface for a specific height.
func (sf *QueryFactory) QueryAt(height int64) (Query, error) {
	state, err := beaconState.NewImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &beaconQuerier{state}, nil
}

type beaconQuerier struct {
	state *beaconState.ImmutableState
}

func (bq *beaconQuerier) Beacon(ctx context.Context) ([]byte, error) {
	return bq.state.Beacon()
}

func (app *beaconApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
