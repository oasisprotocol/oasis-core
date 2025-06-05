package beacon

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon/state"
)

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
