package beacon

import (
	"context"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/abci"
	beaconState "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/beacon/state"
)

// Query is the beacon query interface.
type Query interface {
	Beacon(context.Context) ([]byte, error)
	Genesis(context.Context) (*beacon.Genesis, error)
}

// QueryFactory is the beacon query factory.
type QueryFactory struct {
	app *beaconApplication
}

// QueryAt returns the beacon query interface for a specific height.
func (sf *QueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	state, err := beaconState.NewImmutableState(sf.app.state, height)
	if err != nil {
		return nil, err
	}

	// If this request was made from an ABCI app, make sure to use the associated
	// context for querying state instead of the default one.
	if abciCtx := abci.FromCtx(ctx); abciCtx != nil && height == abciCtx.BlockHeight()+1 {
		state.Snapshot = abciCtx.State().ImmutableTree
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
