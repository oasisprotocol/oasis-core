package beacon

import (
	"context"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/beacon"
)

// QueryFactory is a beacon query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is a beacon query implementation.
type Query interface {
	// Beacon returns the beacon.
	Beacon(context.Context) ([]byte, error)
	// Epoch returns the current epoch.
	Epoch(context.Context) (beacon.EpochTime, int64, error)
	// FutureEpoch returns the future epoch.
	FutureEpoch(context.Context) (*beacon.EpochTimeState, error)
	// VRFState returns the VRF state.
	VRFState(context.Context) (*beacon.VRFState, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*beacon.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*beacon.ConsensusParameters, error)
}

// StateQueryFactory is a beacon state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new beacon query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a beacon query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
