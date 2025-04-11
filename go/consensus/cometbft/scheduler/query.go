package scheduler

import (
	"context"

	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/scheduler"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

// QueryFactory is a scheduler query factory implementation.
type QueryFactory interface {
	// QueryAt returns a query for the given block height.
	QueryAt(ctx context.Context, height int64) (Query, error)
}

// Query is the scheduler query interface.
type Query interface {
	// CurrentValidators returns a list of validators.
	Validators(context.Context) ([]*scheduler.Validator, error)
	// AllCommittees returns a list of all elected committees.
	AllCommittees(context.Context) ([]*scheduler.Committee, error)
	// KindsCommittees returns a list of all committees of specific kinds.
	KindsCommittees(context.Context, []scheduler.CommitteeKind) ([]*scheduler.Committee, error)
	// Genesis returns the genesis state.
	Genesis(context.Context) (*scheduler.Genesis, error)
	// ConsensusParameters returns the consensus parameters.
	ConsensusParameters(context.Context) (*scheduler.ConsensusParameters, error)
}

// StateQueryFactory is a scheduler state query factory.
type StateQueryFactory struct {
	querier *app.QueryFactory
}

// NewStateQueryFactory returns a new scheduler query factory
// backed by the given application state.
func NewStateQueryFactory(state abciAPI.ApplicationState) QueryFactory {
	return &StateQueryFactory{
		querier: app.NewQueryFactory(state),
	}
}

// QueryAt returns a scheduler query for a specific height.
func (f *StateQueryFactory) QueryAt(ctx context.Context, height int64) (Query, error) {
	return f.querier.QueryAt(ctx, height)
}
