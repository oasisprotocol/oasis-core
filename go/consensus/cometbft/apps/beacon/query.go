package beacon

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state"
)

// QueryFactory is the beacon query factory.
type QueryFactory struct {
	state abciAPI.ApplicationQueryState
}

// NewQueryFactory returns a new beacon query factory
// backed by the given application state.
func NewQueryFactory(state abciAPI.ApplicationQueryState) *QueryFactory {
	return &QueryFactory{
		state: state,
	}
}

// QueryAt returns a beacon query for a specific height.
func (f *QueryFactory) QueryAt(ctx context.Context, height int64) (*Query, error) {
	state, err := abciAPI.NewImmutableStateAt(ctx, f.state, height)
	if err != nil {
		return nil, err
	}
	return NewQuery(beaconState.NewImmutableState(state)), nil
}

// Query is the beacon query.
type Query struct {
	state *beaconState.ImmutableState
}

// NewQuery returns a new beacon query backed by the given state.
func NewQuery(state *beaconState.ImmutableState) *Query {
	return &Query{
		state: state,
	}
}

// Beacon implements beacon.Query.
func (q *Query) Beacon(ctx context.Context) ([]byte, error) {
	return q.state.Beacon(ctx)
}

// Epoch implements beacon.Query.
func (q *Query) Epoch(ctx context.Context) (beacon.EpochTime, int64, error) {
	return q.state.GetEpoch(ctx)
}

// FutureEpoch implements beacon.Query.
func (q *Query) FutureEpoch(ctx context.Context) (*beacon.EpochTimeState, error) {
	return q.state.GetFutureEpoch(ctx)
}

// ConsensusParameters implements beacon.Query.
func (q *Query) ConsensusParameters(ctx context.Context) (*beacon.ConsensusParameters, error) {
	return q.state.ConsensusParameters(ctx)
}

// VRFState implements beacon.Query.
func (q *Query) VRFState(ctx context.Context) (*beacon.VRFState, error) {
	return q.state.VRFState(ctx)
}
