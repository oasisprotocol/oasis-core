package beacon

import (
	"context"
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
	state, err := newImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}
	return &beaconQuerier{state}, nil
}

type beaconQuerier struct {
	state *immutableState
}

func (bq *beaconQuerier) Beacon(ctx context.Context) ([]byte, error) {
	return bq.state.GetBeacon()
}

func (app *beaconApplication) QueryFactory() interface{} {
	return &QueryFactory{app}
}
